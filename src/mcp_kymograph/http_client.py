"""The driver's channel over Streamable HTTP (revision 2025-06-18).

:class:`HttpClientChannel` has the interface of :class:`~mcp_kymograph.driver.ClientChannel` —
``open``, ``send``, ``read_line``, ``close_write``, ``close`` — so that the driver, unchanged,
speaks its script into it and reads lines out of it. What the channel does with a line is HTTP:
one exchange per ``send`` on a connection of its own (``POST``, ``Connection: close``), the
session and protocol version the server named, the answer as a JSON body or as an event stream
read as it arrives, and a ``DELETE`` at the end. What only HTTP knows — a status that carries no
answer, a session the server lost, an endpoint that is not there, one that speaks only the old
HTTP+SSE transport, a TLS handshake that failed — is not a line: it is
:attr:`HttpClientChannel.failure`, a reason the driver writes into the step that went unanswered,
instead of a silence; for ``tls``, with the library's text in
:attr:`~HttpClientChannel.failure_detail`.

Which generation a request is in, the channel reads off the request: one whose ``params._meta``
names a protocol version (``io.modelcontextprotocol/protocolVersion``) is modern, and goes out
with ``MCP-Protocol-Version``, ``Mcp-Method`` and, where it applies, ``Mcp-Name``, and with no
session (2026-07-28); any other is legacy, with the session and version the server named. In
modern, an answer whose head came (200) and whose body ended before the answer to its id did is
:attr:`HttpClientChannel.failure` ``stream_broken``, and the driver sends it again. In legacy, a
stream that ended after an event id, with the answer outstanding, is resumed with a ``GET`` and
``Last-Event-ID`` (2025-11-25: the server "MAY close the connection" and the client resumes), up to
:data:`MAX_RESUMES` times; when that does not bring the answer, the failure is the same.

The channel is a client, not a browser and not a forwarder. It sends no ``Origin``, follows no
redirect, and never connects anywhere but the endpoint it was given. It sends an ``Authorization``
header only with a :class:`~mcp_kymograph.credentials.Token` it was handed, and the secret headers
it was handed, in every head it writes and to that one endpoint (http-transport.md 2.8); a 401 or
a 403 is :attr:`HttpClientChannel.failure` ``unauthorized``, with the parsed challenge beside it.
No flow gets a token: the URL of a ``resource_metadata`` is read to be named, never fetched. The
URI of an old-transport ``endpoint`` event is read to name the transport and never used.
Everything a server decides is bounded: a head by
:data:`~mcp_kymograph.http.head.MAX_HEAD_BYTES` and :data:`~mcp_kymograph.http.head.MAX_FIELDS`, a
message by ``max_message_bytes``, and what is read ahead of the driver by the queue's size.
Memory never grows with a body past those bounds.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import socket
import ssl
import unicodedata
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from mcp_kymograph.credentials import SecretHeader, Token
from mcp_kymograph.driver import OVERSIZED
from mcp_kymograph.eras import META_VERSION, PROBE_METHOD
from mcp_kymograph.events import (
    HTTP_SSE_ONLY,
    HTTP_STATUS,
    HTTP_UNREACHABLE,
    MAX_READ_DEPTH,
    RATE_LIMITED,
    SESSION_LOST,
    STREAM_BROKEN,
    TLS,
    UNAUTHORIZED,
    load_bytes,
)
from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES
from mcp_kymograph.http.body import JsonBodyFramer
from mcp_kymograph.http.head import Head
from mcp_kymograph.http.message import (
    BODY,
    END,
    FRAMING_ERROR,
    HEAD,
    HttpFramer,
    Piece,
)
from mcp_kymograph.http.sse import SseFramer
from mcp_kymograph.masking import parse_challenge

#: A way to make the channel's connection, given the time it may take: the proxy's front. It keeps
#: to that time itself, so that it can say which part ran out — the connection (an ordinary
#: error, ``http_unreachable``) or the TLS handshake on it (:class:`HandshakeFailed`).
Connect = Callable[[float], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]

#: How long ``connect`` and the writing of a request may take, and the GET that looks for the
#: old transport. Not the answer's time: that is the driver's step timeout.
DEFAULT_CONNECT_TIMEOUT = 10.0

#: How long the body of a 401 or 403 is read, under a token observation, for the code of its
#: error and for nothing else. Short on purpose: the refusal is the result and is known from the
#: head, so a server that stalls or trickles in its body must not hold the step. The driver's
#: wait for the step ends the read at the latest, whatever is left of this.
REJECTION_BODY_SECONDS = 2.0

#: A read from the connection. Small, so that what the channel holds besides a head stays small.
_READ_BYTES = 16 * 1024

#: Lines read ahead of the driver. A server that streams faster than the driver reads is not
#: read faster than that: the socket is left unread, and the server waits.
_QUEUE_LINES = 16

#: The most a session id may be, and its characters (visible ASCII, no space): what can be sent
#: back in a header field without it being anything else.
_MAX_SESSION_LENGTH = 1024
_MAX_VERSION_LENGTH = 32

#: How many times a legacy stream is resumed for one answer, and the longest wait for the
#: server's ``retry`` before a resumption (the driver's step time bounds all of it).
MAX_RESUMES = 3
MAX_RESUME_WAIT = 5.0
#: A header value the channel took from the server (an event id) and sends back: visible ASCII.
_MAX_EVENT_ID = 1024

#: The methods whose request names its object in ``Mcp-Name`` (2026-07-28), and the member that
#: does: a tool's or prompt's name; for a resource, the URI.
_NAMED = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}

#: What the old-transport probe reads of the stream before it gives up looking for ``endpoint``.
_PROBE_BYTES = 64 * 1024

#: The most of a TLS library's text kept as a failure's detail, and the characters dropped from
#: it first: those a terminal acts on or does not show, as ``cli.display`` drops them.
MAX_FAILURE_DETAIL = 300
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

#: How much longer than its connect time the channel waits for a :data:`Connect` that keeps to
#: the time itself, and how much longer than the handshake's own time asyncio's bound on it is:
#: backstops, so that the time that decides is the one that can say what ran out.
_BACKSTOP_SECONDS = 1.0

#: The schemes a URL may have. ``https`` is spoken through the system's trust store, the name
#: checked, nothing about it configurable (http-transport.md 8.1).
SCHEMES = ("http", "https")

_JSON = "application/json"
_STREAM = "text/event-stream"


@dataclass(slots=True)
class _Exchange:
    """One request on its own connection, and the way its answer comes back."""

    expects_answer: bool
    initialize: bool
    identifier: Any
    with_session: bool
    first_initialize: bool
    #: The version of a modern request (from its ``_meta``), or None for a legacy one; and the
    #: method and ``Mcp-Name`` its headers carry.
    modern_version: str | None = None
    method: str = ""
    name: str | None = None
    probe: bool = False
    #: What has been seen of the answer: its status, whether the answer to the request's id was
    #: delivered, whether the body broke (a framing error, an event cut short) or held a message
    #: too large or too broken to read, and the stream's last event id and ``retry``.
    status: int = 0
    answered: bool = False
    broken: bool = False
    unreadable: bool = False
    last_event_id: str | None = None
    retry: int | None = None
    resuming: bool = False
    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(_QUEUE_LINES))
    writer: asyncio.StreamWriter | None = None
    task: asyncio.Task | None = None
    ended: bool = False  # the None has been handed out


class HttpClientChannel:
    """The driver's side of a Streamable HTTP endpoint: lines in, lines out, reasons beside."""

    def __init__(
        self,
        url: str,
        *,
        connect: Connect | None = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        notice: Callable[[str], None] | None = None,
        token: Token | None = None,
        headers: Sequence[SecretHeader] = (),
        observe: bool = False,
    ) -> None:
        self._scheme, self._host, self._port, self._target = _parse_url(url)
        # The two references to the token that the run holds besides the masker's literal set.
        self._token = token
        self._headers = tuple(headers)
        #: Under a token observation the body of a 401 or 403 is read for its error code; else
        #: the answer ends at the head.
        self._observe = observe
        self._unauthorized_status: int | None = None
        self._answer_status: int | None = None
        self._rejection_code: int | None = None
        self._challenge: dict[str, Any] | None = None
        self._tls_context: ssl.SSLContext | None = None
        self._connect_fn = connect
        self._connect_timeout = connect_timeout
        self._max_message_bytes = max_message_bytes
        self._notice = notice
        self._session: str | None = None
        self._version: str | None = None
        self._initialize_sent = False
        self._last_initialize_first = False
        self._failure: str | None = None
        self._failure_detail = ""
        self._retry_after: int | None = None
        self._rate_limit_status: int | None = None
        #: Set by the driver around the one request it sends again after a ``Retry-After`` wait.
        #: Not reset by ``send``.
        self.after_wait = False
        self._exchange: _Exchange | None = None
        self._closed = False
        self._peak = 0

    # -- what the driver reads beside the lines ---------------------------------------------

    @property
    def failure(self) -> str | None:
        """Why the last exchange has no answer (``http_status``, ``session_lost``,
        ``http_unreachable``, ``http_sse_only``, ``tls``, ``unauthorized``), or None. Reset by
        every ``send``."""
        return self._failure

    @property
    def retry_after(self) -> int | None:
        """Under ``rate_limited``, the seconds the answer's ``Retry-After`` asked for, or None:
        no such header, more than one, or one that is not delta-seconds (an HTTP-date is not
        waited for). Reset by every ``send``."""
        return self._retry_after

    @property
    def rate_limit_status(self) -> int | None:
        """Under ``rate_limited``, the status (429 or 503) of the answer. Reset by every
        ``send``."""
        return self._rate_limit_status

    @property
    def unauthorized_status(self) -> int | None:
        """The status (401 or 403) of the last answer that was :data:`UNAUTHORIZED`, or None.
        Kept after the exchange, not reset by ``send``: the terminal says it at the end."""
        return self._unauthorized_status

    @property
    def answer_status(self) -> int | None:
        """The HTTP status of the final head the last ``send`` drew, or None when none came.
        Reset by every ``send``; a token observation records it per exchange."""
        return self._answer_status

    @property
    def rejection_code(self) -> int | None:
        """The ``error.code`` of the body of the last 401 or 403, when that body is a JSON-RPC
        error object with a whole number there, else None. Only the number is read; no text of
        the body is kept. Reset by every ``send``."""
        return self._rejection_code

    @property
    def challenge(self) -> dict[str, Any] | None:
        """The first ``Bearer`` challenge of that answer's ``WWW-Authenticate``, parsed and not
        masked (:func:`~mcp_kymograph.masking.parse_challenge`), or None: ``resource_metadata``,
        ``scope`` and ``error`` are in ``["params"]``. What is shown of it goes through the
        masker and ``display``."""
        return self._challenge

    @property
    def failure_detail(self) -> str:
        """Under ``tls``, how the handshake failed: the TLS library's text, the system's for a
        connection broken off, ours for a handshake not finished in time — the characters a
        terminal must not be handed removed, at most :data:`MAX_FAILURE_DETAIL` characters, not
        masked (the recorder masks). Empty for every other failure, and reset by every
        ``send``."""
        return self._failure_detail

    @property
    def peak_buffered_bytes(self) -> int:
        """The most the channel held of a head, a body or an event at any one time."""
        return self._peak

    # -- the interface of ClientChannel -----------------------------------------------------

    async def open(self) -> None:
        """Nothing to open: each exchange makes its own connection."""

    async def send(self, line: bytes) -> None:
        """Write one message as a request and return; the answer is read in the background.

        Never raises because of the server: a connection that cannot be made is a
        :attr:`failure` and the end of the exchange, which the driver finds when it reads.
        """
        if self._closed:
            raise ConnectionError("the HTTP channel is closed")
        await self._end_exchange()
        self._failure = None
        self._failure_detail = ""
        self._retry_after = None
        self._rate_limit_status = None
        self._answer_status = None
        self._rejection_code = None
        document, _ = load_bytes(line, MAX_READ_DEPTH)
        is_object = isinstance(document, dict)
        expects_answer = is_object and "method" in document and "id" in document
        initialize = expects_answer and document["method"] == "initialize"
        version, name = _modern(document) if is_object else (None, None)
        method = document.get("method") if is_object else None
        # The ``initialize`` sent again after a ``Retry-After`` wait is the same request: it is the
        # first one if the one before it was.
        first_initialize = initialize and (
            not self._initialize_sent or (self.after_wait and self._last_initialize_first)
        )
        exchange = _Exchange(
            expects_answer=expects_answer,
            initialize=initialize,
            identifier=document.get("id") if is_object else None,
            with_session=version is None and self._session is not None,
            first_initialize=first_initialize,
            modern_version=version,
            method=method if isinstance(method, str) else "",
            name=name,
            probe=version is not None and method == PROBE_METHOD,
        )
        if initialize:
            self._initialize_sent = True
            self._last_initialize_first = first_initialize
        self._exchange = exchange
        try:
            reader, writer = await self._connect()
        except (HandshakeFailed, ssl.SSLError) as error:
            # The endpoint was reached and the handshake on the connection did not complete:
            # whatever the cause, not unreachable.
            self._failure = TLS
            self._failure_detail = _detail(str(error))
            exchange.queue.put_nowait(None)
            return
        except Exception:  # noqa: BLE001 - any other way of not getting a connection is the same
            self._failure = HTTP_UNREACHABLE
            exchange.queue.put_nowait(None)
            return
        exchange.writer = writer
        body = line.rstrip(b"\r\n")
        head = self._request_head("POST", with_body=len(body), exchange=exchange)
        try:
            writer.write(head + body)
            await asyncio.wait_for(writer.drain(), self._connect_timeout)
        except Exception:  # noqa: BLE001, S110 - the answer, if any, is still read
            # A server may answer and close before it has read all of the request. What it
            # said is worth more than that it hung up; with nothing to read, the end before the
            # head is reported as it is.
            pass
        exchange.task = asyncio.create_task(self._read(exchange, reader), name="http-exchange")

    async def read_line(self, timeout: float) -> bytes | None:
        """The next line of the answer, :data:`~mcp_kymograph.driver.OVERSIZED` for one that
        could not be read, None at the end of the exchange. Raises
        :class:`asyncio.TimeoutError` on time, as the stdio channel does."""
        exchange = self._exchange
        if exchange is None or exchange.ended:
            return None
        line = await asyncio.wait_for(exchange.queue.get(), timeout)
        if line is None:
            exchange.ended = True
        return line

    async def goodbye(self, timeout: float) -> None:
        """End the session with ``DELETE``, if there is one. The answer is read and dropped
        (405 is allowed); the time is ``timeout`` in all."""
        if self._session is None or self._closed:
            return
        await self._end_exchange()
        try:
            await asyncio.wait_for(self._delete(), timeout)
        except Exception:  # noqa: BLE001, S110 - the goodbye of a client that is leaving
            pass
        finally:
            self._session = None

    def close_write(self) -> None:
        """Close the open connection and stop reading; further sends are refused. May be
        called again."""
        self._closed = True
        exchange, self._exchange = self._exchange, None
        if exchange is not None:
            _stop(exchange)

    def close(self) -> None:
        self.close_write()

    # -- connecting and requests ------------------------------------------------------------

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._connect_fn is not None:
            return await asyncio.wait_for(
                self._connect_fn(self._connect_timeout),
                self._connect_timeout + _BACKSTOP_SECONDS,
            )
        if self._scheme == "https" and self._tls_context is None:
            # The channel on its own, without a proxy in front: TLS as the proxy makes it.
            self._tls_context = ssl.create_default_context()
        return await connect_to(
            self._host, self._port, context=self._tls_context, timeout=self._connect_timeout
        )

    def _request_head(
        self,
        method: str,
        *,
        with_body: int | None = None,
        exchange: _Exchange | None = None,
        resume: str | None = None,
    ) -> bytes:
        host = f"[{self._host}]" if ":" in self._host else self._host
        lines = [f"{method} {self._target} HTTP/1.1", f"Host: {host}:{self._port}"]
        if method == "POST":
            lines += [
                "Content-Type: application/json",
                "Accept: application/json, text/event-stream",
                f"Content-Length: {with_body}",
            ]
        elif method == "GET":
            lines.append("Accept: text/event-stream")
        lines.append("Connection: close")
        # To the one origin the channel connects to, in every head it writes: 2.8 has the header
        # in every request, and the old-transport probe and the DELETE are requests.
        if self._token is not None:
            lines.append(f"Authorization: {self._token.authorization()}")
        lines += [f"{header.name}: {header.reveal()}" for header in self._headers]
        if exchange is not None and exchange.modern_version is not None:
            # The modern era: no session; version, method and name in the head (2026-07-28).
            lines.append(f"MCP-Protocol-Version: {exchange.modern_version}")
            lines.append(f"Mcp-Method: {exchange.method}")
            if exchange.name is not None:
                lines.append(f"Mcp-Name: {_header_value(exchange.name)}")
        elif method != "GET" or resume is not None:
            if self._version is not None:
                lines.append(f"MCP-Protocol-Version: {self._version}")
            if self._session is not None:
                lines.append(f"Mcp-Session-Id: {self._session}")
        if resume is not None:
            lines.append(f"Last-Event-ID: {resume}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")

    async def _end_exchange(self) -> None:
        exchange, self._exchange = self._exchange, None
        if exchange is not None:
            _stop(exchange)
            if exchange.task is not None:
                await asyncio.gather(exchange.task, return_exceptions=True)

    async def _delete(self) -> None:
        reader, writer = await self._connect()
        try:
            writer.write(self._request_head("DELETE"))
            await writer.drain()
            framer = HttpFramer(request=False)
            framer.expect("DELETE")
            while True:
                data = await reader.read(_READ_BYTES)
                pieces = framer.feed(data) if data else framer.finish()
                if any(piece.kind in (HEAD, FRAMING_ERROR) for piece in pieces) or not data:
                    return
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    # -- reading an answer ------------------------------------------------------------------

    async def _read(self, exchange: _Exchange, reader: asyncio.StreamReader) -> None:
        """The background task of one exchange: lines into the queue, then None."""
        try:
            try:
                await self._read_answer(exchange, reader)
                await self._after_answer(exchange)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - never a silent end for a bug in reading
                await exchange.queue.put(OVERSIZED)
            await exchange.queue.put(None)
        finally:
            _stop(exchange)

    async def _after_answer(self, exchange: _Exchange) -> None:
        """An answer's head came and its body ended without the answer to the request's id: in
        the modern era the stream is broken and the request is lost; in legacy, a stream that
        gave an event id is resumed, and broken when that does not bring the answer. A legacy
        stream that gave no id ends as it always did: no answer, for the driver to name. The
        probe is neither: a server that answers it with nothing readable is not a modern one."""
        if (
            self._failure is not None
            or not exchange.expects_answer
            or exchange.answered
            or exchange.status != 200
            or exchange.unreadable
            or exchange.probe
        ):
            return
        if exchange.modern_version is None and (
            exchange.last_event_id is None or await self._resume(exchange)
        ):
            return
        self._failure = STREAM_BROKEN

    async def _resume(self, exchange: _Exchange) -> bool:
        """Resume the stream with ``GET`` and ``Last-Event-ID``, as the server's last event id
        and ``retry`` say, up to :data:`MAX_RESUMES` times. True when the answer came or the
        endpoint refused the credentials (the failure is set); False when it did not."""
        exchange.resuming = True
        for _ in range(MAX_RESUMES):
            event_id = exchange.last_event_id
            if not _sendable_id(event_id):
                return False
            wait = min((exchange.retry or 0) / 1000, MAX_RESUME_WAIT)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                reader, writer = await self._connect()
            except Exception:  # noqa: BLE001 - a connection that fails ends the resuming
                return False
            if exchange.writer is not None:
                with contextlib.suppress(Exception):
                    exchange.writer.close()
            exchange.writer = writer
            exchange.status = 0
            try:
                writer.write(self._request_head("GET", resume=event_id))
                await asyncio.wait_for(writer.drain(), self._connect_timeout)
            except Exception:  # noqa: BLE001, S110 - what the server said is still read
                pass
            await self._read_answer(exchange, reader, method="GET")
            if exchange.answered or self._failure is not None:
                return True
            if exchange.status != 200:
                return False
        return False

    async def _read_answer(
        self, exchange: _Exchange, reader: asyncio.StreamReader, *, method: str = "POST"
    ) -> None:
        framer = HttpFramer(request=False)
        framer.expect(method)
        reply = _Reply()
        while True:
            try:
                if reply.rejected:
                    # Only an error code is wanted of this body, and only for so long as
                    # REJECTION_BODY_SECONDS in all: a server that stalls in it does not turn the
                    # refusal into a silence.
                    left = reply.until - asyncio.get_running_loop().time()
                    if left <= 0:
                        raise asyncio.TimeoutError
                    data = await asyncio.wait_for(reader.read(_READ_BYTES), left)
                else:
                    data = await reader.read(_READ_BYTES)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                data = b""  # a reset is an end, and says no more than that
            pieces = framer.feed(data) if data else framer.finish()
            self._note(framer.buffered_bytes + reply.buffered_bytes)
            for piece in pieces:
                if await self._piece(exchange, reply, piece):
                    return
            if not data:
                if reply.head is None:
                    self._failure = HTTP_UNREACHABLE  # the end came before any head
                return

    async def _piece(self, exchange: _Exchange, reply: _Reply, piece: Piece) -> bool:
        """Act on one piece of the answer. True when the exchange is over."""
        if piece.kind == FRAMING_ERROR:
            # A head that does not parse or is too large, or a body whose framing cannot be
            # trusted: nothing can be read from it, and it is not a silence.
            exchange.broken = True
            await exchange.queue.put(OVERSIZED)
            return True
        if piece.kind == HEAD:
            assert piece.head is not None  # noqa: S101 - a HEAD piece has its head
            status = piece.head.status or 0
            if 100 <= status < 200 and status != 101:
                reply.interim = True  # the final answer to the same request follows
                return False
            reply.head = piece.head
            exchange.status = status
            self._answer_status = status
            return await self._head(exchange, reply, piece.head, status)
        if reply.interim:
            if piece.kind == END:
                reply.interim = False
            return False
        if piece.kind == BODY:
            return await self._body(exchange, reply, piece.payload)
        if piece.kind == END:
            await self._end(exchange, reply, complete=piece.complete)
            return True
        return False

    async def _head(self, exchange: _Exchange, reply: _Reply, head: Head, status: int) -> bool:
        if status == 202 and not exchange.expects_answer:
            return True  # accepted: a notification has no answer
        if exchange.resuming and status not in (401, 403, 200):
            return True  # the resumption was refused: the caller decides, no reason of its own
        if status in (401, 403):
            self._failure = UNAUTHORIZED
            self._unauthorized_status = status
            self._challenge = parse_challenge(head.values("www-authenticate"))
            if not self._observe or _media_type(head) != _JSON:
                return True
            # The body is read for the number of its error and for nothing else, under the
            # limits of every answer and a time of its own; it is never delivered as a message.
            reply.body = JsonBodyFramer(self._max_message_bytes)
            reply.rejected = True
            reply.until = asyncio.get_running_loop().time() + REJECTION_BODY_SECONDS
            return False
        if status in (429, 503):
            seconds = _delta_seconds(head.values("retry-after"))
            # A 429 is a limit with or without the header; a 503 is one only where it names a
            # wait in seconds, and is an ordinary failing status otherwise, unless the request
            # is the one sent after a wait: then either status is the limit again.
            if status == 429 or seconds is not None or self.after_wait:
                self._failure = RATE_LIMITED
                self._retry_after = seconds
                self._rate_limit_status = status
                return True
        if status == 400 and exchange.probe and _media_type(head) == _JSON:
            # The versioning page: "inspect the body of a 400 Bad Request". The driver reads a
            # modern error out of it; with nothing readable the reason stands, and is legacy.
            self._failure = HTTP_STATUS
            reply.body = JsonBodyFramer(self._max_message_bytes)
            return False
        if status != 200:
            if status == 404 and exchange.with_session:
                self._failure = SESSION_LOST
            else:
                self._failure = HTTP_STATUS
                if exchange.first_initialize and status in (400, 404, 405):
                    await self._probe_old_transport()
            return True
        if exchange.initialize and not exchange.resuming:
            self._take_session(head)
        mediatype = _media_type(head)
        if mediatype == _JSON:
            reply.body = JsonBodyFramer(self._max_message_bytes)
        elif mediatype == _STREAM:
            reply.body = SseFramer(self._max_message_bytes)
        else:
            reply.body = None  # any body at all is a body that cannot be read
        return False

    async def _body(self, exchange: _Exchange, reply: _Reply, payload: bytes) -> bool:
        if reply.body is None:
            if payload:
                await exchange.queue.put(OVERSIZED)
                return True
            return False
        if isinstance(reply.body, SseFramer):
            for event in reply.body.feed(payload):
                await self._event(exchange, event, reply.body)
        else:
            reply.body.feed(payload)
        return False

    async def _end(self, exchange: _Exchange, reply: _Reply, *, complete: bool) -> None:
        if isinstance(reply.body, SseFramer):
            for event in reply.body.finish():
                await self._event(exchange, event, reply.body)
            if not complete:
                exchange.broken = True
                # The body's framing (a length, the chunks) ended before it said so, between two
                # events: the answer may have been in what never came. Not the end of a stream
                # the server closed on purpose, and not a silence.
                await exchange.queue.put(OVERSIZED)
        elif isinstance(reply.body, JsonBodyFramer) and reply.rejected:
            for frame in reply.body.finish(complete=complete):
                if not (frame.truncated or frame.incomplete):
                    self._rejection_code = _error_code(frame.data)
        elif isinstance(reply.body, JsonBodyFramer):
            for frame in reply.body.finish(complete=complete):
                if frame.truncated or frame.incomplete:
                    # Too large to hold, or cut short by the connection: the second is a
                    # stream that broke, the first an answer nobody can read.
                    if frame.truncated:
                        exchange.unreadable = True
                    else:
                        exchange.broken = True
                    await exchange.queue.put(OVERSIZED)
                    continue
                # The body is the whole message. One that is no JSON is not a message cut
                # short by the framing, but it is as unreadable as one that is: a line the
                # driver would read past, ending the step with nothing said about why.
                document, too_deep = load_bytes(frame.data, MAX_READ_DEPTH)
                if document is None and not too_deep:
                    exchange.unreadable = True
                    await exchange.queue.put(OVERSIZED)
                else:
                    await self._deliver(exchange, frame.data)

    async def _event(self, exchange: _Exchange, event: Any, framer: SseFramer) -> None:
        # What a resumption needs: the stream's last event id, unless it was too long to keep,
        # and the last ``retry``.
        exchange.last_event_id = None if event.id_lost else event.event_id
        exchange.retry = framer.retry
        if event.truncated or event.incomplete:
            if event.truncated:
                exchange.unreadable = True
            else:
                exchange.broken = True
            await exchange.queue.put(OVERSIZED)
        elif event.is_message:
            await self._deliver(exchange, event.data)

    async def _deliver(self, exchange: _Exchange, data: bytes) -> None:
        if exchange.initialize and self._version is None:
            self._take_version(data, exchange.identifier)
        if not exchange.answered:
            document, _ = load_bytes(data, MAX_READ_DEPTH)
            exchange.answered = (
                isinstance(document, dict)
                and "method" not in document
                and not isinstance(document.get("id"), bool)
                and document.get("id") == exchange.identifier
            )
        await exchange.queue.put(data)

    # -- what the server names --------------------------------------------------------------

    def _take_session(self, head: Head) -> None:
        values = head.values("mcp-session-id")
        if not values:
            return
        value = values[0]
        if (
            len(values) == 1
            and 0 < len(value) <= _MAX_SESSION_LENGTH
            and all(0x21 <= ord(char) <= 0x7E for char in value)
        ):
            self._session = value
            return
        # The value is not repeated: a session id is as good as a password to the session.
        if self._notice is not None:
            self._notice("the server sent an Mcp-Session-Id that cannot be used; no session")

    def _take_version(self, data: bytes, identifier: Any) -> None:
        document, _ = load_bytes(data, MAX_READ_DEPTH)
        if not isinstance(document, dict) or "method" in document:
            return
        if document.get("id") != identifier or isinstance(document.get("id"), bool):
            return
        result = document.get("result")
        version = result.get("protocolVersion") if isinstance(result, dict) else None
        if (
            isinstance(version, str)
            and 0 < len(version) <= _MAX_VERSION_LENGTH
            and all(char in "0123456789-" for char in version)
        ):
            self._version = version

    # -- the old transport ------------------------------------------------------------------

    async def _probe_old_transport(self) -> None:
        """One ``GET``: does this endpoint open an event stream whose first event is
        ``endpoint``? Then it speaks HTTP+SSE only, and that is the reason. The URI in the
        event is not used. Anything else leaves the reason as it was."""
        try:
            if await asyncio.wait_for(self._look_for_endpoint(), self._connect_timeout):
                self._failure = HTTP_SSE_ONLY
        except Exception:  # noqa: BLE001, S110 - a probe that fails finds nothing
            pass

    async def _look_for_endpoint(self) -> bool:
        reader, writer = await self._connect()
        try:
            writer.write(self._request_head("GET"))
            await writer.drain()
            framer = HttpFramer(request=False)
            framer.expect("GET")
            events = SseFramer(self._max_message_bytes)
            streaming = False
            read = 0
            while read <= _PROBE_BYTES:
                data = await reader.read(_READ_BYTES)
                read += len(data)
                for piece in framer.feed(data) if data else framer.finish():
                    if piece.kind == FRAMING_ERROR:
                        return False
                    if piece.kind == HEAD:
                        head = piece.head
                        assert head is not None  # noqa: S101
                        if head.status != 200 or _media_type(head) != _STREAM:
                            return False
                        streaming = True
                    elif piece.kind == BODY and streaming:
                        for event in events.feed(piece.payload):
                            return event.event_type == "endpoint"
                if not data:
                    return False
            return False
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    def _note(self, held: int) -> None:
        self._peak = max(self._peak, held)


@dataclass(slots=True)
class _Reply:
    """What has been read of one answer so far."""

    head: Head | None = None
    interim: bool = False
    #: The head was 401 or 403 and its body is read for an error code only.
    rejected: bool = False
    #: The loop time at which that body is no longer waited for.
    until: float = 0.0
    body: JsonBodyFramer | SseFramer | None = None

    @property
    def buffered_bytes(self) -> int:
        return self.body.buffered_bytes if self.body is not None else 0


def _error_code(data: bytes) -> int | None:
    """The whole number at ``error.code`` of a JSON-RPC error object, else None."""
    document, _ = load_bytes(data, MAX_READ_DEPTH)
    error = document.get("error") if isinstance(document, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    return code if type(code) is int else None


def _stop(exchange: _Exchange) -> None:
    """Close the connection of an exchange and stop its reader. Safe to repeat."""
    if exchange.writer is not None:
        with contextlib.suppress(Exception):
            exchange.writer.close()
    if exchange.task is not None and not exchange.task.done():
        task = asyncio.current_task()
        if exchange.task is not task:
            exchange.task.cancel()


def _delta_seconds(values: list[str]) -> int | None:
    """The seconds of a ``Retry-After`` that is exactly one header of ASCII digits (RFC 9110,
    10.2.3), else None. A number too long to be a wait this tool could ever make is clamped, not
    refused: it will not fit the step, and says so by that."""
    if len(values) != 1:
        return None
    text = values[0].strip()
    if not (text.isascii() and text.isdigit()):
        return None
    return int(text) if len(text) <= 9 else 10**9


def _media_type(head: Head) -> str | None:
    """The media type of a response, lower case, or None if it has not exactly one."""
    values = head.values("content-type")
    if len(values) != 1:
        return None
    return values[0].partition(";")[0].strip().lower()


class HandshakeFailed(Exception):
    """The connection to the endpoint was made and the TLS handshake on it did not complete. The
    text says how: the TLS library's words, the system's for a connection broken off, or ours
    for a handshake not finished in its time."""


async def connect_to(
    host: str, port: int, *, context: ssl.SSLContext | None, timeout: float
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """A connection to ``host`` and ``port`` within ``timeout`` seconds in all, over TLS with
    ``context`` unless it is None.

    The TCP connection first: a failure or a timeout there is raised as it is, an endpoint that
    could not be reached. Then, from the moment the connection is up, every way the handshake
    on it does not complete is :class:`HandshakeFailed` — a certificate refused, a connection
    reset or closed, a peer that never answers — within the time that is left, and no bound of
    asyncio's longer than that decides it."""
    if context is None:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    loop = asyncio.get_running_loop()
    began = loop.time()
    sock = await asyncio.wait_for(_tcp(host, port), timeout)
    left = max(timeout - (loop.time() - began), 0.001)
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(
                sock=sock,
                ssl=context,
                server_hostname=host,
                ssl_handshake_timeout=left + _BACKSTOP_SECONDS,
            ),
            left,
        )
    except asyncio.TimeoutError:
        sock.close()
        raise HandshakeFailed(
            f"the TLS handshake did not finish within {round(left, 1):g} s"
        ) from None
    except ssl.SSLError as error:
        sock.close()
        said = str(error) or f"the TLS handshake failed ({type(error).__name__})"
        raise HandshakeFailed(said) from error
    except (OSError, EOFError) as error:
        sock.close()
        said = str(error)
        raise HandshakeFailed(
            "the connection ended during the TLS handshake"
            + (f": {said}" if said else f" ({type(error).__name__})")
        ) from error
    except BaseException:
        sock.close()
        raise


async def _tcp(host: str, port: int) -> socket.socket:
    """A connected, non-blocking socket to the first address of ``host`` that takes one, as
    ``asyncio.open_connection`` would make it; the last address's error if none does."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    failure: OSError = OSError(f"no address for {host}")
    for family, kind, proto, _, address in infos:
        sock = socket.socket(family, kind, proto)
        try:
            sock.setblocking(False)
            await loop.sock_connect(sock, address)
        except OSError as error:
            sock.close()
            failure = error
            continue
        except BaseException:
            sock.close()
            raise
        return sock
    raise failure


def _modern(document: dict[str, Any]) -> tuple[str | None, str | None]:
    """The version a request names in ``params._meta`` — which makes it a modern request — and
    the name its ``Mcp-Name`` header carries (the tool's, the prompt's or the resource's URI), or
    None for each that is not there. A version is digits and hyphens, at most
    :data:`_MAX_VERSION_LENGTH` of them; anything else is no version the channel sends."""
    params = document.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    version = meta.get(META_VERSION) if isinstance(meta, dict) else None
    if not (
        isinstance(version, str)
        and 0 < len(version) <= _MAX_VERSION_LENGTH
        and all(char in "0123456789-" for char in version)
    ):
        return None, None
    member = _NAMED.get(document.get("method"))
    name = params.get(member) if member is not None else None
    return version, name if isinstance(name, str) else None


def _header_value(value: str) -> str:
    """A name as a header value (2026-07-28): as it is when it is visible ASCII (0x21 to 0x7E, no
    space), otherwise ``=?base64?…?=`` of its UTF-8."""
    plain = (
        value != ""
        and all(0x21 <= ord(char) <= 0x7E for char in value)
        and not value.startswith("=?base64?")
    )
    if plain:
        return value
    return "=?base64?" + base64.b64encode(value.encode("utf-8", "replace")).decode("ascii") + "?="


def _sendable_id(value: str | None) -> bool:
    """Whether an event id the server sent can be sent back as a header value: non-empty,
    visible ASCII, no longer than :data:`_MAX_EVENT_ID`. Nothing else leaves the channel."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= _MAX_EVENT_ID
        and all(0x21 <= ord(char) <= 0x7E for char in value)
    )


def _detail(text: str) -> str:
    """A TLS library's text as a failure's detail: without the characters of
    :data:`_UNSAFE_CATEGORIES`, then cut to :data:`MAX_FAILURE_DETAIL`."""
    kept = "".join(c for c in text if unicodedata.category(c) not in _UNSAFE_CATEGORIES)
    return kept[:MAX_FAILURE_DETAIL]


def _parse_url(url: str) -> tuple[str, str, int, str]:
    """Scheme, host, port and request target of an ``http://`` or ``https://`` URL with a host,
    a port and a path; ValueError for anything else."""
    if not isinstance(url, str) or any(ord(char) <= 0x20 or ord(char) >= 0x7F for char in url):
        raise ValueError("the URL must be printable ASCII without spaces")
    parts = urlsplit(url)
    if parts.scheme not in SCHEMES:
        raise ValueError("only http:// and https:// URLs are spoken")
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("the URL must carry no user, password or fragment")
    host = parts.hostname
    try:
        port = parts.port
    except ValueError:
        raise ValueError("the URL's port is not a port") from None
    if not host or port is None or not parts.path.startswith("/"):
        raise ValueError("the URL needs a host, a port and a path")
    target = parts.path + (f"?{parts.query}" if parts.query else "")
    return parts.scheme, host, port, target
