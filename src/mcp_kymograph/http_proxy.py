"""The proxy for Streamable HTTP: the driver's channel on one side, the endpoint on the other.

Same contract as :mod:`mcp_kymograph.proxy`, over HTTP/1.1 instead of pipes. The driver's
:class:`~mcp_kymograph.http_client.HttpClientChannel` is given :meth:`HttpProxy.front_connect` as
its way to connect: every connection it makes is one end of a ``socketpair``, and the other end
belongs to a forwarding task that opens exactly one connection to the target — the host and
port of the endpoint, nowhere else, no redirect followed — and moves bytes both ways, unchanged
and as they arrive. A copy of every read goes to an :class:`HttpObserver`, which finds where
heads and bodies begin and end (:mod:`mcp_kymograph.http.message`), never reads MCP itself, and
hands the messages it finds to the inspector and the recorder exactly as the stdio observer
does.

The separation stays as in the stdio proxy: ``HttpObserver.request`` and ``.response`` are
synchronous and never raise, nothing in them waits, and the sink drops rather than blocks. An
error in the observer ends observation (recorded, ``observer_error``), not the connection;
the byte counts then go on counting every byte as body, the side on which a run is never read
as silent. A framing error does the same for its connection: the rest is passed through, and
counted, unread.

**What is counted** (``client_input_bytes``, ``server_output_bytes``) are body bytes: what the
requests and responses carried, without heads and without chunk framing. Bytes the framer could
not tell apart from a body (after a framing error) count as body.

**TLS** to an ``https://`` endpoint is made here, on the forwarding side, with the system's trust
store and nothing configurable (http-transport.md 8.1); the driver's leg stays a socket pair and
the observer reads plaintext. Each connection's version and leaf certificate go into its
``http_request`` events, and the run's set into ``run_finished.http.tls``; a handshake that fails
is the channel's ``tls``.

**No rules.** Changing a message needs it whole, and over HTTP that means re-framing bodies and
event streams while forwarding them. Discovery does not need it; an engine with rules is
refused at construction.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import socket
import ssl
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from functools import partial
from typing import Any

from mcp_kymograph.authorization import Declaration
from mcp_kymograph.engine import Engine
from mcp_kymograph.events import MAX_READ_DEPTH, TRANSPORT_HTTP, Direction, Mode, load_bytes
from mcp_kymograph.http.body import BodyFrame, JsonBodyFramer
from mcp_kymograph.http.head import Head
from mcp_kymograph.http.message import (
    BODY,
    END,
    FRAMING_ERROR,
    GAP,
    HEAD,
    PASSTHROUGH,
    HttpFramer,
    Piece,
)
from mcp_kymograph.http.sse import SseEvent, SseFramer
from mcp_kymograph.http_client import (
    DEFAULT_CONNECT_TIMEOUT,
    HandshakeFailed,
    _parse_url,
    connect_to,
)
from mcp_kymograph.inspection import NOTHING_SEEN, Inspector
from mcp_kymograph.pacing import Paced
from mcp_kymograph.proxy import (
    READ_SIZE,
    Limits,
    Observer,
    Proxy,
    RunOutcome,
    _Budget,
)
from mcp_kymograph.recorder import TRUST_STORE_VARIABLES, Recorder, endpoint_refusal
from mcp_kymograph.sink import EventSink
from mcp_kymograph.verdict import EXIT_INCOMPLETE

#: How long the target may go on answering after the driver's side of a connection has closed.
#: The only client is our own channel, which closes the whole connection when it has what it
#: wanted; a target that holds a stream open after that is not waited for.
CLIENT_CLOSED_GRACE_SECONDS = 1.0

#: The most requests one connection may have sent without an answer to each before the
#: observer stops reading it. Our channel sends one; this bounds the exchanges held.
MAX_PIPELINED = 64

#: The most distinct session ids numbered. Past it a session is recorded as none: the id is
#: never kept, and the table does not grow with what a server hands out.
MAX_SESSIONS = 1024

RESPONSE_CLASSES = ("2xx", "3xx", "4xx", "5xx", "other")

_JSON = "application/json"
_STREAM = "text/event-stream"


@dataclass
class _Tally:
    """What the run counts, shared by all connections: ordinals, session numbers, the
    counts of ``run_finished``. Only ever touched on the event loop."""

    connections: int = 0
    exchanges: int = 0
    streams: int = 0
    events: int = 0
    framing_errors: int = 0
    client_input_bytes: int = 0
    server_output_bytes: int = 0
    responses: dict[str, int] = field(default_factory=lambda: dict.fromkeys(RESPONSE_CLASSES, 0))
    sessions: dict[str, int] = field(default_factory=dict)
    #: Over ``https``: the versions and leaf certificates of every connection made, distinct.
    #: None over plain HTTP, where there is no set to give.
    tls_versions: set[str] | None = None
    tls_certificates: set[str] | None = None

    def session(self, values: Sequence[str]) -> int | None:
        """The ordinal of the (first) session id among ``values``; the id itself goes nowhere."""
        if not values:
            return None
        known = self.sessions.get(values[0])
        if known is None:
            if len(self.sessions) >= MAX_SESSIONS:
                return None
            known = self.sessions[values[0]] = len(self.sessions) + 1
        return known

    def as_dict(self) -> dict[str, Any]:
        return {
            "exchanges": self.exchanges,
            "responses": dict(self.responses),
            "streams": self.streams,
            "events": self.events,
            "framing_errors": self.framing_errors,
            "tls": None
            if self.tls_versions is None or self.tls_certificates is None
            else {
                "versions": sorted(self.tls_versions),
                "certificates": sorted(self.tls_certificates),
            },
        }


@dataclass(slots=True)
class _Exchange:
    """One request and its answer, as far as the observer has seen."""

    number: int
    connection: int
    method: str
    head_bytes: int
    request_body: JsonBodyFramer
    request_bytes: int = 0
    response_bytes: int = 0
    response_body: JsonBodyFramer | SseFramer | None = None
    stream: int | None = None
    #: The JSON-RPC method of the request, when its body was one request: what an answer in
    #: this exchange answers. A notification is answered by nothing, a batch by no one method.
    rpc_method: str | None = None
    events: int = 0
    comments: int = 0
    ended: bool = False


class HttpObserver:
    """One connection's copy of the traffic, a framer for each direction.

    Holds no stream and no writer: there is nothing here the connection could wait on.
    """

    def __init__(
        self,
        *,
        sink: EventSink,
        recorder: Recorder,
        inspector: Inspector,
        notes: dict[Direction, Observer],
        tally: _Tally,
        connection: int,
        max_message_bytes: int,
        tls: dict[str, str] | None = None,
    ) -> None:
        self._sink = sink
        #: This connection's TLS (``version``, ``certificate_sha256``), or None over plain
        #: HTTP: what every request read on it is recorded with.
        self._tls = tls
        self._recorder = recorder
        self._inspector = inspector
        self._notes = notes
        self._tally = tally
        self._connection = connection
        self._max = max_message_bytes
        self._requests = HttpFramer(request=True)
        self._responses = HttpFramer(request=False)
        #: Exchanges without a final response yet, oldest first: the one a response answers is
        #: the first. HTTP/1.1 answers in order.
        self._pending: deque[_Exchange] = deque()
        #: The exchange whose request is still being read.
        self._reading: _Exchange | None = None
        self._interim = False
        self._broken = False
        self._disabled = False
        #: Which side's end-of-file came first: "client", "target", or "shutdown".
        self._first: str | None = None
        #: The sides whose reader saw its peer's end-of-file. A body the close delimits ended
        #: there, and only there: where we stopped reading, it was cut.
        self._eof: set[str] = set()

    # -- what the forwarding side calls -----------------------------------------------------

    def request(self, chunk: bytes) -> None:
        """A copy of one read from the driver's side. Synchronous, and never raises."""
        self._feed(chunk, self._requests, request=True)

    def response(self, chunk: bytes) -> None:
        """A copy of one read from the target. Synchronous, and never raises."""
        self._feed(chunk, self._responses, request=False)

    def reader_ended(self, side: str) -> None:
        """A side read end-of-file. The first to do so is the one that closed first."""
        self._eof.add(side)
        if self._first is None:
            self._first = "client" if side == "request" else "target"

    def shutting_down(self) -> None:
        """We are closing the connection: neither side closed first."""
        if self._first is None:
            self._first = "shutdown"

    def end(self, side: str) -> None:
        """One direction is over: close out what it was in the middle of."""
        if self._disabled or self._broken:
            return
        framer = self._requests if side == "request" else self._responses
        try:
            pieces = framer.finish()
            if side not in self._eof:
                # The peer did not close: we stopped reading, because the driver's side had
                # closed or the run is ending. A body the close would have delimited (an event
                # stream held open, most often) did not end; it was cut, and says so.
                pieces = [replace(p, complete=False) if p.kind == END else p for p in pieces]
            self._handle(pieces, request=side == "request")
        except Exception:  # noqa: BLE001 - observation may fail; the connection may not
            self._give_up()

    def close(self) -> None:
        """Both directions are over. An exchange not ended by now never got to its end."""
        if self._disabled or self._broken:
            return
        try:
            ended = "client_closed" if self._first == "client" else "closed"
            for exchange in list(self._pending):
                self._end_exchange(exchange, ended)
            if self._reading is not None and not self._reading.ended:
                self._end_exchange(self._reading, ended)
        except Exception:  # noqa: BLE001
            self._give_up()

    # -- feeding ----------------------------------------------------------------------------

    def _feed(self, chunk: bytes, framer: HttpFramer, *, request: bool) -> None:
        if self._disabled or self._broken:
            self._count(request, len(chunk))
            return
        try:
            pieces = framer.feed(chunk)
        except Exception:  # noqa: BLE001 - the framer failing is observation failing
            self._count(request, len(chunk))
            self._give_up()
            return
        self._count_pieces(pieces, request)
        try:
            self._handle(pieces, request=request)
        except Exception:  # noqa: BLE001 - same rule, a step later
            self._give_up()

    def _count(self, request: bool, size: int) -> None:
        if request:
            self._tally.client_input_bytes += size
        else:
            self._tally.server_output_bytes += size

    def _count_pieces(self, pieces: list[Piece], request: bool) -> None:
        for piece in pieces:
            if piece.kind == BODY:
                self._count(request, len(piece.payload))
            elif piece.kind == PASSTHROUGH:
                self._count(request, len(piece.raw))

    def _handle(self, pieces: list[Piece], *, request: bool) -> None:
        for piece in pieces:
            kind = piece.kind
            if kind == FRAMING_ERROR:
                self._fail()
            elif self._broken or kind in (GAP, PASSTHROUGH):
                continue
            elif request:
                self._request_piece(piece)
            else:
                self._response_piece(piece)

    def _give_up(self) -> None:
        self._disabled = True
        self._sink.stop_observing(from_seq=self._sink.assigned, reason="observer_error")

    def _fail(self) -> None:
        """A framing error, or what amounts to one: from here only passing through. The
        exchanges not yet ended end saying so."""
        if self._broken:
            return
        self._tally.framing_errors += 1
        for exchange in list(self._pending):
            self._end_exchange(exchange, "framing_error")
        if self._reading is not None and not self._reading.ended:
            self._end_exchange(self._reading, "framing_error")
        self._broken = True

    # -- requests ---------------------------------------------------------------------------

    def _request_piece(self, piece: Piece) -> None:
        if piece.kind == HEAD:
            assert piece.head is not None  # noqa: S101 - a HEAD piece has its head
            self._request_head(piece.head)
        elif piece.kind == BODY:
            exchange = self._reading
            if exchange is not None:
                exchange.request_bytes += len(piece.payload)
                exchange.request_body.feed(piece.payload)
        elif piece.kind == END:
            exchange, self._reading = self._reading, None
            if exchange is not None:
                for frame in exchange.request_body.finish(complete=piece.complete):
                    self._frame(exchange, Direction.CLIENT_TO_SERVER, frame)

    def _request_head(self, head: Head) -> None:
        if len(self._pending) >= MAX_PIPELINED:
            self._fail()
            return
        assert head.method is not None and head.target is not None  # noqa: S101
        self._tally.exchanges += 1
        exchange = _Exchange(
            number=self._tally.exchanges,
            connection=self._connection,
            method=head.method,
            head_bytes=head.size_bytes,
            request_body=JsonBodyFramer(self._max),
        )
        self._pending.append(exchange)
        self._reading = exchange
        self._responses.expect(head.method)
        emit = partial(
            self._recorder.http_request,
            exchange=exchange.number,
            connection=self._connection,
            method=head.method,
            target=head.target,
            headers=head.fields,
            session=self._tally.session(head.values("mcp-session-id")),
            tls=self._tls,
        )
        self._sink.offer(emit, kind="http_request")

    # -- responses --------------------------------------------------------------------------

    def _response_piece(self, piece: Piece) -> None:
        if piece.kind == HEAD:
            assert piece.head is not None  # noqa: S101
            self._response_head(piece.head)
            return
        if self._interim:
            if piece.kind == END:
                self._interim = False
            return
        if not self._pending:
            return
        exchange = self._pending[0]
        if piece.kind == BODY:
            exchange.response_bytes += len(piece.payload)
            self._response_body(exchange, piece.payload)
        elif piece.kind == END:
            cut = self._flush_response(exchange, complete=piece.complete)
            # A body that the close delimits is complete by its framing; an event the stream
            # ended in the middle of is not, and the exchange says so.
            self._end_exchange(
                exchange, "complete" if piece.complete and not cut else self._cut_short()
            )

    def _cut_short(self) -> str:
        return "client_closed" if self._first == "client" else "closed"

    def _response_head(self, head: Head) -> None:
        status = head.status or 0
        if 100 <= status < 200 and status != 101:
            self._interim = True  # the final answer to the same request follows
            return
        if not self._pending:
            self._fail()  # an answer to nothing we saw asked: the pairing cannot be trusted
            return
        exchange = self._pending[0]
        exchange.head_bytes += head.size_bytes
        framing = _framing_of(head, exchange.method)
        if framing == "json":
            exchange.response_body = JsonBodyFramer(self._max)
        elif framing == "sse":
            exchange.response_body = SseFramer(self._max)
            self._tally.streams += 1
            exchange.stream = self._tally.streams
        self._tally.responses[_class_of(status)] += 1
        types = head.values("content-type")
        emit = partial(
            self._recorder.http_response,
            exchange=exchange.number,
            status=status,
            reason=head.reason or "",
            headers=head.fields,
            content_type=types[0] if types else None,
            framing=framing,
            session=self._tally.session(head.values("mcp-session-id")),
        )
        self._sink.offer(emit, kind="http_response")

    def _response_body(self, exchange: _Exchange, payload: bytes) -> None:
        body = exchange.response_body
        if isinstance(body, SseFramer):
            for event in body.feed(payload):
                self._event(exchange, event)
            self._count_events(exchange, body)
        elif body is not None:
            body.feed(payload)

    def _flush_response(self, exchange: _Exchange, *, complete: bool) -> bool:
        """Close out the response body. True if what ended it was cut: an event or a document
        the stream or the body did not get to the end of."""
        body, exchange.response_body = exchange.response_body, None
        cut = False
        if isinstance(body, SseFramer):
            for event in body.finish():
                cut = cut or event.incomplete
                self._event(exchange, event)
            self._count_events(exchange, body)
        elif isinstance(body, JsonBodyFramer):
            for frame in body.finish(complete=complete):
                cut = cut or frame.incomplete
                self._frame(exchange, Direction.SERVER_TO_CLIENT, frame)
        return cut

    def _count_events(self, exchange: _Exchange, framer: SseFramer) -> None:
        self._tally.events += framer.events - exchange.events
        exchange.events = framer.events
        exchange.comments = framer.comments

    def _end_exchange(self, exchange: _Exchange, ended: str) -> None:
        if exchange.ended:
            return
        if exchange.response_body is not None:
            self._flush_response(exchange, complete=False)
        exchange.ended = True
        with contextlib.suppress(ValueError):
            self._pending.remove(exchange)
        emit = partial(
            self._recorder.http_end,
            exchange=exchange.number,
            ended=ended,
            request_body_bytes=exchange.request_bytes,
            response_body_bytes=exchange.response_bytes,
            head_bytes=exchange.head_bytes,
            events=exchange.events,
            comments=exchange.comments,
        )
        self._sink.offer(emit, kind="http_end")

    # -- messages ---------------------------------------------------------------------------

    def _frame(self, exchange: _Exchange, direction: Direction, frame: BodyFrame) -> None:
        whole = not frame.truncated and not frame.incomplete
        if direction is Direction.CLIENT_TO_SERVER:
            if whole:
                exchange.rpc_method = _request_method(frame.data)
            responded = None
        else:
            # A JSON body is the answer to this exchange's request and to no other, whatever
            # id it gives; only a whole one that names a method is a request of its own.
            responded = None if whole and _names_method(frame.data) else exchange.rpc_method
        self._message(
            exchange,
            direction,
            frame.data,
            size_bytes=frame.size_bytes,
            truncated=frame.truncated,
            incomplete=frame.incomplete,
            responded_method=responded,
        )

    def _event(self, exchange: _Exchange, event: SseEvent) -> None:
        if not event.is_message:
            return  # counted, not a message
        # A stream carries requests and notifications of the server's as well as the answer:
        # an event answers this exchange's request when it is whole and names no method.
        whole = not event.truncated and not event.incomplete
        answers = whole and _names_method(event.data) is False
        self._message(
            exchange,
            Direction.SERVER_TO_CLIENT,
            event.data,
            size_bytes=event.size_bytes,
            truncated=event.truncated,
            incomplete=event.incomplete,
            event_id=None if event.id_lost else event.event_id,
            responded_method=exchange.rpc_method if answers else None,
        )

    def _message(
        self,
        exchange: _Exchange,
        direction: Direction,
        raw: bytes,
        *,
        size_bytes: int,
        truncated: bool,
        incomplete: bool,
        responded_method: str | None,
        event_id: str | None = None,
    ) -> None:
        # A truncated or unfinished message is not inspected: there is nothing whole to parse,
        # and a signal found in half a message would be an observation about our own framing.
        whole = not truncated and not incomplete
        look = self._inspector.look(direction, raw) if whole else NOTHING_SEEN
        emit = partial(
            self._recorder.message,
            direction=direction,
            raw=raw,
            size_bytes=size_bytes,
            truncated=truncated,
            incomplete=incomplete,
            transport=TRANSPORT_HTTP,
            responded_method=responded_method,
            exchange=exchange.number,
            stream=exchange.stream,
            event_id=event_id,
        )
        self._sink.offer(emit, kind="message")
        if look.observations or look.evaluations or look.answered_initialize:
            # After the message, and pointing back at the number it just took (see
            # Observer._submit): read, not passed, because `offer` assigns it inside.
            seq = self._sink.assigned
            notes = self._notes[direction]
            notes._record_name(look, message_seq=seq)
            notes._record_observations(look, message_seq=seq)
            notes._record_statements(look, message_seq=seq)


def _request_method(raw: bytes) -> str | None:
    """The method of a body that is one JSON-RPC request (an object with a string ``method``
    and an ``id``), else None."""
    document, too_deep = load_bytes(raw, MAX_READ_DEPTH)
    if too_deep or not isinstance(document, dict) or "id" not in document:
        return None
    method = document.get("method")
    return method if isinstance(method, str) else None


def _names_method(raw: bytes) -> bool | None:
    """Whether a message is an object with a ``method`` (a request or a notification, never
    an answer), or None where that cannot be read: no JSON, or deeper than is read."""
    document, too_deep = load_bytes(raw, MAX_READ_DEPTH)
    if too_deep or document is None:
        return None
    return isinstance(document, dict) and "method" in document


def _framing_of(head: Head, method: str) -> str:
    """What a response's body is, for the recording: ``json``, ``sse``, ``empty`` or ``other``."""
    status = head.status or 0
    if method.upper() == "HEAD" or status in (204, 304) or 100 <= status < 200:
        return "empty"
    if not head.values("transfer-encoding"):
        lengths = head.values("content-length")
        if lengths and all(value.strip() == "0" for value in lengths):
            return "empty"
    types = head.values("content-type")
    media = types[0].partition(";")[0].strip().lower() if len(types) == 1 else None
    if media == _JSON:
        return "json"
    if media == _STREAM:
        return "sse"
    return "other"


def _class_of(status: int) -> str:
    return f"{status // 100}xx" if 200 <= status < 600 else "other"


class HttpProxy(Proxy):
    """Runs one session over HTTP: no server to start, connections to forward, a run to close.

    ``Proxy``'s sink, recorder, inspector, signal handling and closing event are used as they
    are; what is different is everything that has a child process or a pipe in it.
    """

    def __init__(
        self,
        *,
        endpoint: str,
        recorder: Recorder,
        limits: Limits,
        engine: Engine | None = None,
        declaration: Declaration | None = None,
        notice: Callable[[str], None] = lambda message: None,
        mode: Mode = Mode.PROXY,
        script: str | None = None,
        script_digest: str | None = None,
        script_vars: dict[str, str] | None = None,
        statements: Sequence[Any] = (),
        scenario_name: str | None = None,
        server_identity: Any = None,
        server_name: str | None = None,
        reproduction: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        isolation: str = "host",
        auth: dict[str, Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        stop_check: Callable[[], bool] | None = None,
        probe: dict[str, Any] | None = None,
        pacing: dict[str, Any] | None = None,
        paced: Paced | None = None,
    ) -> None:
        if engine is not None and engine.active:
            raise ValueError("rules are not carried out over HTTP: only observation is")
        scheme, self._host, self._port, _ = _parse_url(endpoint)
        refusal = endpoint_refusal(endpoint)
        if refusal is not None:
            raise ValueError(refusal)  # run_started would refuse it, after the run had begun
        super().__init__(
            argv=[],
            recorder=recorder,
            limits=limits,
            client_in=None,  # there are no pipes
            client_out=None,
            engine=engine,
            declaration=declaration,
            notice=notice,
            mode=mode,
            script=script,
            script_digest=script_digest,
            script_vars=script_vars,
            statements=statements,
            scenario_name=scenario_name,
            server_identity=server_identity,
            server_name=server_name,
            reproduction=reproduction,
            inputs=inputs,
            sandbox=None,
            isolation=isolation,
            auth=auth,
            clock=clock,
            stop_check=stop_check,
            probe=probe,
        )
        self._endpoint = endpoint
        #: What ``run_started.pacing`` records (mcp_kymograph.pacing.Pacing.as_dict), or None for
        #: a run that is not paced; and the wait the run made before it began, written as
        #: ``paced`` right after ``run_started``.
        self._pacing = pacing
        self._paced = paced
        self._tally = _Tally()
        #: Over ``https``: one context for the run, as the standard library makes it — the
        #: system's trust store, the name checked, a certificate required — with nothing set on
        #: it. And whether the variables OpenSSL reads for that store were set, never their values.
        self._tls_context: ssl.SSLContext | None = None
        self._trust_store_env: dict[str, bool] | None = None
        if scheme == "https":
            self._tls_context = ssl.create_default_context()
            self._trust_store_env = {name: name in os.environ for name in TRUST_STORE_VARIABLES}
            self._tally.tls_versions, self._tally.tls_certificates = set(), set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._ending = False
        self._notes = {
            direction: Observer(
                sink=self._sink,
                recorder=recorder,
                direction=direction,
                max_message_bytes=limits.max_message_bytes,
                inspector=self._inspector,
                declared_server=server_name,
            )
            for direction in (Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT)
        }

    @property
    def ready(self) -> bool:
        """There is no child to wait for: the target is somebody else's, and a connection
        that cannot be made is the channel's to report."""
        return True

    # -- the front --------------------------------------------------------------------------

    async def front_connect(
        self, timeout: float = DEFAULT_CONNECT_TIMEOUT
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """A connection for the channel: one end of a socket pair. The other end is forwarded,
        byte for byte, over one connection of its own to the target.

        That connection is made first, within ``timeout``: the time the channel gives connecting
        (the step timeout, in ``drive --http``). A target that cannot be reached is a connection
        the channel does not get, and reports as ``http_unreachable``. Over ``https`` the
        handshake follows on the connection, in the time that is left, and every way it does not
        complete is :class:`~mcp_kymograph.http_client.HandshakeFailed`, which the channel
        reports as ``tls`` (:func:`~mcp_kymograph.http_client.connect_to`). A handshake that
        completed is in the run's set."""
        if self._ending:
            raise ConnectionError("the proxy has ended")
        target_reader, target_writer = await connect_to(
            self._host, self._port, context=self._tls_context, timeout=timeout
        )
        if self._tls_context is None:
            tls = None
        else:
            try:
                tls = self._connection_tls(target_writer)
            except BaseException:
                target_writer.close()
                raise
        near: socket.socket | None = None
        far: socket.socket | None = None
        try:
            if self._ending:
                raise ConnectionError("the proxy has ended")
            near, far = socket.socketpair()
            near.setblocking(False)
            far.setblocking(False)
            reader, writer = await asyncio.open_connection(sock=near)
        except BaseException:
            for end in (near, far):
                if end is not None:
                    end.close()
            target_writer.close()
            raise
        self._tally.connections += 1
        observer = HttpObserver(
            sink=self._sink,
            recorder=self._recorder,
            inspector=self._inspector,
            notes=self._notes,
            tally=self._tally,
            connection=self._tally.connections,
            max_message_bytes=self._limits.max_message_bytes,
            tls=tls,
        )
        task = asyncio.create_task(
            self._serve(far, target_reader, target_writer, observer), name="http-connection"
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return reader, writer

    def _connection_tls(self, writer: asyncio.StreamWriter) -> dict[str, str]:
        """The version a connection negotiated and its leaf certificate's SHA-256 as presented
        (DER), added to the run's set — on the forwarding path, which drops nothing."""
        ssl_object = writer.get_extra_info("ssl_object")
        version = ssl_object.version() if ssl_object is not None else None
        der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if version is None or der is None:
            # A verified handshake always has both; without them nothing can be said about it.
            raise HandshakeFailed("the TLS connection named no version or no certificate")
        tls = {"version": version, "certificate_sha256": hashlib.sha256(der).hexdigest()}
        assert self._tally.tls_versions is not None  # noqa: S101 - set with the context
        assert self._tally.tls_certificates is not None  # noqa: S101
        self._tally.tls_versions.add(tls["version"])
        self._tally.tls_certificates.add(tls["certificate_sha256"])
        return tls

    async def _serve(
        self,
        far: socket.socket,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
        observer: HttpObserver,
    ) -> None:
        """One front connection, to its end. A failure here is this connection's."""
        writers: list[asyncio.StreamWriter] = [target_writer]
        pumps: list[asyncio.Task[None]] = []
        try:
            try:
                front_reader, front_writer = await asyncio.open_connection(sock=far)
            except BaseException:
                far.close()
                raise
            writers.append(front_writer)
            up = asyncio.create_task(
                self._pump(front_reader, target_writer, observer, "request"), name="http-up"
            )
            down = asyncio.create_task(
                self._pump(target_reader, front_writer, observer, "response"), name="http-down"
            )
            pumps += [up, down]
            await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
            if up.done() and not down.done():
                # The driver's side closed. What the target is still saying goes nowhere; it
                # gets a moment to finish, not the connection's idle time.
                await asyncio.wait({down}, timeout=CLIENT_CLOSED_GRACE_SECONDS)
        except asyncio.CancelledError:
            observer.shutting_down()
            raise
        except Exception as error:  # noqa: BLE001 - collected here, or it would vanish unretrieved
            self._notice(f"forwarding failed: {type(error).__name__}")
        finally:
            for task in pumps:
                task.cancel()
            for writer in writers:
                with contextlib.suppress(Exception):
                    writer.close()
            if pumps:
                await asyncio.gather(*pumps, return_exceptions=True)
            observer.close()

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        observer: HttpObserver,
        side: str,
    ) -> None:
        """Move bytes one way. The observer gets the copy first — synchronously — so that a
        request is known before any answer to it can be read, then the bytes go on."""
        feed = observer.request if side == "request" else observer.response
        try:
            while True:
                try:
                    chunk = await reader.read(READ_SIZE)
                except (ConnectionError, OSError):
                    chunk = b""  # a reset is an end, and says no more than that
                if not chunk:
                    observer.reader_ended(side)
                    return
                if side == "request" and self._stop_file_stops():
                    # The kill switch, before anything of the client's goes on to the target.
                    return
                feed(chunk)
                try:
                    writer.write(chunk)
                    await writer.drain()  # where backpressure arrives
                except (ConnectionError, OSError):
                    return  # the other end is gone; its own pump finds that out by reading
        finally:
            observer.end(side)
            # Pass the end on: without us, the other side would have seen it.
            with contextlib.suppress(Exception):
                if side == "request" and writer.can_write_eof():
                    writer.write_eof()
                else:
                    writer.close()

    # -- the run ----------------------------------------------------------------------------

    async def run(self) -> RunOutcome:
        started = time.monotonic_ns()
        self._sink.start()
        await self._sink.put(
            partial(
                self._recorder.run_started,
                argv=[],
                limits=self._limits.as_dict(),
                inputs=self._inputs,
                authorization=self._declaration.as_dict(),
                pacing_enforced=True if self._pacing is not None else None,
                pacing=self._pacing,
                probe=self._probe,
                mode=self._mode.value,
                script=self._script,
                script_digest=self._script_digest,
                script_vars=self._script_vars,
                server_identity=(
                    None if self._server_identity is None else self._server_identity.to_dict()
                ),
                scenario_name=self._scenario_name,
                server_name=self._server_name,
                reproduction=self._reproduction,
                isolation=self._isolation,
                transport=TRANSPORT_HTTP,
                endpoint=self._endpoint,
                auth=self._auth,
                trust_store_env=self._trust_store_env,
            ),
            kind="run_started",
        )
        if self._paced is not None:
            await self._sink.put(
                partial(self._recorder.paced, seconds=self._paced.seconds, why=self._paced.why),
                kind="paced",
            )
        handlers = self._install_signal_handlers()
        timer = asyncio.create_task(self._duration_limit(), name="duration-limit")
        watcher = asyncio.create_task(self._watch_stop_file(), name="stop-file")
        self.launched.set()  # no child to wait for
        try:
            reason = await self._until_over()
            return await self._shut_down_http(reason, started)
        finally:
            self.launched.set()
            self._ending = True
            timer.cancel()
            watcher.cancel()
            await asyncio.gather(timer, watcher, return_exceptions=True)
            self._remove_signal_handlers(handlers)
            for task in list(self._tasks):
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _until_over(self) -> str:
        """Wait for what ends the run: the driver done with its channel and every connection
        closed, or a stop (a signal, the duration limit)."""
        stopped = asyncio.create_task(self._stop.wait(), name="stop-requested")
        finished = asyncio.create_task(self._until_finished(), name="client-finished")
        try:
            done, _ = await asyncio.wait({stopped, finished}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (stopped, finished):
                task.cancel()
            await asyncio.gather(stopped, finished, return_exceptions=True)
        return (self._stop_reason or "stopped") if stopped in done else "client_closed"

    async def _until_finished(self) -> None:
        if self.client_settled is None:
            await asyncio.Event().wait()  # someone else's client: only a stop ends this
        await self.client_settled.wait()
        while self._tasks:
            await asyncio.wait(set(self._tasks))

    async def _shut_down_http(self, reason: str, started: int) -> RunOutcome:
        budget = _Budget(self._limits.shutdown_budget_seconds, self._limits.final_write_seconds)

        # Connections still open are closed, in the budget. Closing them is what lets the
        # driver finish, if a stop interrupted it.
        self._ending = True
        open_connections = {task for task in self._tasks if not task.done()}
        for task in open_connections:
            task.cancel()
        if open_connections:
            await asyncio.wait(open_connections, timeout=budget.remaining())

        if self.client_settled is not None:
            # Our own client half writes how its script ended before the closing event, not
            # after it, where nothing is read. Bounded, and outside the budget.
            paused = time.monotonic()
            settle = self._limits.client_settle_seconds
            try:
                await asyncio.wait_for(self.client_settled.wait(), settle)
            except asyncio.TimeoutError:
                self._notice(f"the driver had not settled after {settle:g} s; closing without it")
                await self._sink.put(
                    partial(
                        self._recorder.limit_exceeded,
                        limit="client_settle_seconds",
                        value=settle,
                        unit="seconds",
                    ),
                    kind="limit_exceeded",
                )
            budget.extend(time.monotonic() - paused)

        await self._stop_written()
        unwritten = await self._sink.drain(timeout=budget.remaining())

        tally = self._tally
        self._closing_written = await self._sink.write_final(
            partial(
                self._recorder.run_finished,
                reason=reason,
                duration_ns=time.monotonic_ns() - started,
                dropped_events=self._sink.dropped,
                unwritten_events=unwritten,
                quarantined_rules=self._engine.quarantined,
                observations_by_method=self._inspector.observations_by_method,
                findings_by_statement=self._inspector.findings_by_statement,
                inspection_bounded=self._inspector.bounded_messages,
                announced_server=self._inspector.announced_server,
                server_output_bytes=tally.server_output_bytes,
                client_input_bytes=tally.client_input_bytes,
                server_exited_first=False,
                http=tally.as_dict(),
                window_exceeded=self.window_exceeded(),
            ),
            kind="run_finished",
            timeout=self._limits.final_write_seconds,
        )
        if not self._closing_written:
            self._notice("the recording has no closing event: the final write did not succeed")

        return RunOutcome(
            exit_code=EXIT_INCOMPLETE if self._stopped_by is not None else 0,
            reason=reason,
            message_count=self._recorder.message_count,
            dropped_events=self._sink.dropped,
            unwritten_events=unwritten,
            recording_stopped=self._sink.stalled,
            closing_event_written=self._closing_written,
            quarantined_rules=self._engine.quarantined,
            observations_by_method=self._inspector.observations_by_method,
            findings_by_statement=self._inspector.findings_by_statement,
            server_redactions=self._recorder.server_redactions,
            inspection_bounded=self._inspector.bounded_messages,
            server_output_bytes=tally.server_output_bytes,
            client_input_bytes=tally.client_input_bytes,
            server_exited_first=False,
            stopped=self._stopped_by,
        )
