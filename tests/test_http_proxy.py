"""The proxy for Streamable HTTP (src/mcp_kymograph/http_proxy.py), and ``drive --http``.

Against the test server (tests/fixtures/http_server.py) where it behaves, and against small
stubs where a test needs to see the bytes, or needs the server to say something else. Real
sockets on 127.0.0.1, a thread for the server, the proxy and the driver on the test's own loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_kymograph import cli, verdict
from mcp_kymograph.events import Mode
from mcp_kymograph.http_proxy import HttpProxy
from mcp_kymograph.masking import Masker
from mcp_kymograph.proxy import Limits, Proxy
from mcp_kymograph.recorder import Recorder

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(FIXTURES / "corpus"))

import http_server  # noqa: E402

POISON = FIXTURES / "corpus" / "poison_server.py"
REFERENCE = FIXTURES / "corpus" / "reference_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"


@pytest.fixture
def serve():
    servers = []

    def started(**behaviour):
        server = http_server.serve(0, **behaviour)
        servers.append(server)
        return server, f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def drive_http(tmp_path, url, *extra, name="runs"):
    """One ``drive --http`` run through ``main``: its exit code, recording path and events."""
    out = tmp_path / name
    code = cli.main(["drive", "-q", "--http", url, "--out-dir", str(out), *extra])
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


def drive_stdio(tmp_path, script, name="stdio"):
    out = tmp_path / name
    code = cli.main(["drive", "-q", "--out-dir", str(out), "--", sys.executable, str(script)])
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


def observed(events):
    """What was found, without where on the wire it was: signal, method, surface and path."""
    return sorted(
        (e["method"], e["surface"], e["path"], e["signal"]) for e in of(events, "observation")
    )


# -- 1. the positive control -----------------------------------------------------------


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_the_poison_server_is_found_over_http_as_over_stdio(tmp_path, serve, respond):
    """Fails if the observer does not give the response bodies to the inspector."""
    _, url = serve(variant="poison", respond=respond)
    code, _, over_http = drive_http(tmp_path, url)
    _, _, over_stdio = drive_stdio(tmp_path, POISON)
    assert code == 0
    assert observed(over_stdio), "the control: the stdio run finds something"
    assert observed(over_http) == observed(over_stdio)
    http_end, stdio_end = of(over_http, "run_finished")[0], of(over_stdio, "run_finished")[0]
    assert http_end["observations_by_method"] == stdio_end["observations_by_method"]


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_the_reference_server_finds_nothing_over_http(tmp_path, serve, respond):
    _, url = serve(variant="reference", respond=respond)
    code, path, events = drive_http(tmp_path, url)
    assert code == 0
    assert observed(events) == []
    assert verdict.read(path).state == verdict.COMPLETE


# -- 2. the recording ------------------------------------------------------------------


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_the_recording_says_what_went_over_http(tmp_path, serve, respond):
    _, url = serve(respond=respond)
    _, path, events = drive_http(tmp_path, url)
    started = events[0]
    assert started["type"] == "run_started"
    assert started["transport"] == "streamable-http"
    assert started["argv"] == []
    assert started["endpoint"]["host"] == "127.0.0.1"
    assert started["endpoint"]["path"] == http_server.PATH
    requests, responses = of(events, "http_request"), of(events, "http_response")
    ends = of(events, "http_end")
    assert len(requests) == len(responses) == len(ends) > 3
    assert [e["exchange"] for e in requests] == list(range(1, len(requests) + 1))
    assert all(e["ended"] == "complete" for e in ends)
    assert {e["method"] for e in requests} == {"POST", "DELETE"}
    messages = of(events, "message")
    assert all(m["transport"] == "streamable-http" and m["exchange"] for m in messages)
    # Exchange 1 is the probe, server/discover, which the legacy test server answers 400 as JSON.
    answers = [m for m in messages if m["direction"] == "server_to_client" and m["exchange"] != 1]
    assert answers
    if respond == "stream":
        assert {r["framing"] for r in responses if r["status"] == 200} == {"sse"}
        assert all(m["stream"] is not None for m in answers)
        assert all(m["event_id"] is None or isinstance(m["event_id"], str) for m in answers)
        streams = sorted({m["stream"] for m in answers})
        assert streams == list(range(1, len(streams) + 1))
    else:
        assert {r["framing"] for r in responses if r["status"] == 200} == {"json"}
        assert all(m["stream"] is None for m in answers)
    assert any(r["framing"] == "empty" for r in responses)  # the 202 and the DELETE's 204
    assert verdict.read(path).state == verdict.COMPLETE


def test_a_session_is_its_ordinal_in_the_recording(tmp_path, serve):
    _, url = serve()
    _, _, events = drive_http(tmp_path, url)
    requests = of(events, "http_request")
    assert [r["session"] for r in requests[:2]] == [None, None]  # the probe, initialize: none yet
    assert {r["session"] for r in requests[2:]} == {1}
    assert of(events, "http_response")[1]["session"] == 1  # the answer to initialize gave it


# -- 3. nothing in the clear -----------------------------------------------------------

SESSION = "SESSION-ID-NOBODY-MAY-SEE-0123456789"
BEARER = "Bearer TOPSECRETTOKEN0123456789abcdef"
COOKIE = "sid=COOKIESECRETVALUE0123456789"
SECRETS = ("NOBODY-MAY-SEE", "TOPSECRETTOKEN", "COOKIESECRETVALUE")


class Stub:
    """A target that holds the bytes it receives and answers with what it is told to.

    Reads one request per connection (a head and a ``Content-Length`` body), calls
    ``answer(request_bytes)`` for the whole response, and closes.
    """

    def __init__(self, answer) -> None:
        self.answer = answer
        self.received: list[bytes] = []
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        # A timeout, so that the thread notices ``close``: a thread blocked in accept() on a
        # closed socket keeps its file descriptor's number, and accepts on whichever socket
        # takes that number next — another test's server.
        self._listener.settimeout(0.05)
        self._closed = False
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    def _accept(self) -> None:
        while not self._closed:
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            connection.settimeout(None)
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        with connection:
            connection.settimeout(5)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    more = connection.recv(65536)
                    if not more:
                        break
                    data += more
                head, _, body = data.partition(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    name, _, value = line.partition(b":")
                    if name.strip().lower() == b"content-length":
                        length = int(value)
                while len(body) < length:
                    more = connection.recv(65536)
                    if not more:
                        break
                    body += more
                    data += more
                self.received.append(data)
                connection.sendall(self.answer(data))
            except OSError:
                return

    def close(self) -> None:
        self._closed = True
        self._acceptor.join(5)
        self._listener.close()


def reference_answer(extra_headers: str):
    """The reference server's answers, with ``extra_headers`` on every response."""
    behaviour = http_server.Behaviour(variant="reference")

    def answer(request: bytes) -> bytes:
        head, _, body = request.partition(b"\r\n\r\n")
        if head.startswith(b"DELETE"):
            return f"HTTP/1.1 204 No Content\r\n{extra_headers}Connection: close\r\n\r\n".encode()
        message = json.loads(body)
        if "id" not in message:
            return f"HTTP/1.1 202 Accepted\r\n{extra_headers}Content-Length: 0\r\n\r\n".encode()
        reply = json.dumps(behaviour.answer(message)).encode()
        session = f"Mcp-Session-Id: {SESSION}\r\n" if message["method"] == "initialize" else ""
        return (
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            f"{session}{extra_headers}Content-Length: {len(reply)}\r\nConnection: close\r\n\r\n"
        ).encode() + reply

    return answer


@pytest.fixture
def stub():
    stubs = []

    def started(answer):
        made = Stub(answer)
        stubs.append(made)
        return made

    yield started
    for made in stubs:
        made.close()


def test_no_secret_of_the_wire_is_in_the_recording(tmp_path, stub):
    target = stub(
        reference_answer(f"Authorization: {BEARER}\r\nSet-Cookie: {COOKIE}\r\nX-Note: ok\r\n")
    )
    code, path, events = drive_http(tmp_path, target.url)
    text = path.read_text()
    # The control: the secrets did go over the wire, in both directions, and were recorded.
    assert any(SESSION.encode() in sent for sent in target.received)
    assert of(events, "http_response") and of(events, "http_request")
    assert of(events, "http_response")[0]["headers"]
    for secret in SECRETS:
        assert secret not in text
    assert code == 0


def test_the_session_id_of_the_test_server_is_not_in_the_recording(tmp_path, serve):
    server, url = serve()
    issued: list[str] = []

    class Noting(set):
        def add(self, value):
            issued.append(value)
            super().add(value)

    server.behaviour.sessions = Noting()
    _, path, _ = drive_http(tmp_path, url)
    assert len(issued) == 1
    assert issued[0] not in path.read_text()


# -- 4. forwarded as it came -----------------------------------------------------------


async def through(tmp_path, url, client, *, name="forward"):
    """Run an HttpProxy for ``url`` with ``client(proxy)`` as the only user of its front.
    Returns the outcome and the recording's events."""
    out = tmp_path / name
    out.mkdir()
    path = out / "events.jsonl"
    with Recorder.open(path, run_id="forward", masker=Masker()) as recorder:
        proxy = HttpProxy(endpoint=url, recorder=recorder, limits=Limits(), mode=Mode.DRIVER)
        settled = asyncio.Event()
        proxy.client_settled = settled

        async def converse():
            try:
                await proxy.launched.wait()
                assert proxy.ready and proxy.child_pid is None
                await client(proxy)
            finally:
                settled.set()

        task = asyncio.create_task(converse())
        outcome = await proxy.run()
        await task
    return outcome, [json.loads(line) for line in path.read_text().splitlines()]


async def exchange_raw(proxy, request: bytes) -> bytes:
    """What the target said back to ``request``, as the channel would read it."""
    reader, writer = await proxy.front_connect()
    writer.write(request)
    await writer.drain()
    answer = await asyncio.wait_for(reader.read(), 10)
    writer.close()
    return answer


def test_the_bytes_go_through_unchanged_in_both_directions(tmp_path, stub):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    # Odd on purpose: header case, an unknown field, a body split by nothing the proxy may fix.
    request = (
        b"POST /mcp HTTP/1.1\r\nhOsT: x\r\nX-Odd:   spaced  \r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    )
    reply = b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Odd: \t kept \r\n"
        b"Content-Length: " + str(len(reply)).encode() + b"\r\nConnection: close\r\n\r\n" + reply
    )
    target = stub(lambda received: response)
    heard = []

    async def client(proxy):
        heard.append(await exchange_raw(proxy, request))

    outcome, events = asyncio.run(through(tmp_path, target.url, client))
    assert target.received == [request]
    assert heard == [response]
    (ended,) = of(events, "http_end")
    assert ended["ended"] == "complete"
    assert outcome.client_input_bytes == len(body)
    assert outcome.server_output_bytes == len(reply)


def test_a_chunked_answer_is_forwarded_with_its_chunking_and_counted_by_content(tmp_path, stub):
    request = b"GET /mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n"
        b"\r\n8\r\ndata: {}\r\n4\r\n\n\n\r\n\r\n0\r\n\r\n"
    )
    target = stub(lambda received: response)
    heard = []

    async def client(proxy):
        heard.append(await exchange_raw(proxy, request))

    outcome, events = asyncio.run(through(tmp_path, target.url, client))
    assert heard == [response]
    assert outcome.server_output_bytes == len(b"data: {}\n\n\r\n")
    (ended,) = of(events, "http_end")
    assert (ended["ended"], ended["events"]) == ("complete", 1)


# -- 5. to 7. what the server does wrong -----------------------------------------------


def test_a_wrong_status_is_recorded_and_the_step_is_unanswered(tmp_path, serve):
    _, url = serve(failure="wrong-status")
    code, path, events = drive_http(tmp_path, url)
    (wrong,) = [r for r in of(events, "http_response") if r["status"] == 418]
    assert wrong["exchange"] > 1
    assert [(e["step"], e["reason"]) for e in of(events, "step_unanswered")] == [
        ("tools/list", "http_status")
    ]
    assert code != 0
    assert verdict.read(path).state == verdict.INCOMPLETE


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_aborted_answer_ends_closed_with_no_message_or_an_incomplete_one(
    tmp_path, serve, respond
):
    _, url = serve(respond=respond, failure="aborted-stream")
    code, _, events = drive_http(tmp_path, url)
    broken = [e for e in of(events, "http_end") if e["ended"] != "complete"]
    assert [e["ended"] for e in broken] == ["closed"]
    messages = [m for m in of(events, "message") if m["exchange"] == broken[0]["exchange"]]
    answers = [m for m in messages if m["direction"] == "server_to_client"]
    assert all(m["incomplete"] for m in answers)
    assert code != 0


def test_an_oversized_answer_is_recorded_truncated_and_not_inspected(tmp_path, serve):
    _, url = serve(failure="oversized")
    _, _, events = drive_http(tmp_path, url)
    (cut,) = [m for m in of(events, "message") if m["truncated"]]
    assert cut["direction"] == "server_to_client"
    assert cut["size_bytes"] > 1024 * 1024
    assert cut["transport"] == "streamable-http"
    assert not [o for o in of(events, "observation") if o["message_seq"] == cut["seq"]]


def test_an_answer_past_what_is_inspected_is_counted_as_bounded(tmp_path, serve):
    """The same answer, whole this time: the message limit raised past it. What the inspector
    does not get through is counted (``inspection_bounded``), not passed over."""
    _, url = serve(failure="oversized", oversized_bytes=1500 * 1024)
    _, _, events = drive_http(tmp_path, url, "--max-message-bytes", str(8 * 1024 * 1024))
    assert not [m for m in of(events, "message") if m["truncated"]]
    assert of(events, "run_finished")[0]["inspection_bounded"] >= 1


# -- 8. nobody there -------------------------------------------------------------------


def test_no_target_is_server_failed_and_the_recording_is_closed(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    code, path, events = drive_http(tmp_path, f"http://127.0.0.1:{port}/mcp")
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == "http_unreachable"
    assert events[-1]["type"] == "run_finished"
    assert code == verdict.EXIT_SERVER_FAILED
    assert verdict.read(path).state == verdict.SERVER_FAILED


# -- 9. the counts ---------------------------------------------------------------------


def test_the_counts_are_body_bytes_and_run_finished_says_what_was_forwarded(tmp_path, serve):
    _, url = serve()
    _, _, events = drive_http(tmp_path, url)
    finished = of(events, "run_finished")[0]
    ends = of(events, "http_end")
    assert finished["client_input_bytes"] == sum(e["request_body_bytes"] for e in ends) > 0
    assert finished["server_output_bytes"] == sum(e["response_body_bytes"] for e in ends) > 0
    assert finished["server_exited_first"] is False
    http = finished["http"]
    assert http["exchanges"] == len(of(events, "http_request")) == len(ends)
    # All but the probe, which the legacy test server answers 400.
    assert http["responses"]["2xx"] == len(of(events, "http_response")) - 1
    assert http["responses"]["4xx"] == 1
    assert set(http["responses"]) == {"2xx", "3xx", "4xx", "5xx", "other"}
    assert (http["streams"], http["events"], http["framing_errors"]) == (0, 0, 0)


def test_the_counts_of_a_stream_and_of_a_wrong_status(tmp_path, serve):
    _, url = serve(respond="stream", failure="wrong-status")
    _, _, events = drive_http(tmp_path, url)
    http = of(events, "run_finished")[0]["http"]
    # The probe's 400, and the 418 the failure gives to tools/list.
    assert http["responses"]["4xx"] == 2 and http["responses"]["other"] == 0
    assert http["streams"] == http["events"] >= 2


def test_a_framing_error_is_counted_and_the_rest_passes_through_unread(tmp_path, stub):
    request = b"GET /mcp HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\n123456789"
    target = stub(lambda received: response)
    heard = []

    async def client(proxy):
        heard.append(await exchange_raw(proxy, request))

    outcome, events = asyncio.run(through(tmp_path, target.url, client))
    assert heard == [response]
    (ended,) = of(events, "http_end")
    assert ended["ended"] == "framing_error"
    assert of(events, "run_finished")[0]["http"]["framing_errors"] == 1
    assert outcome.server_output_bytes == len(response)  # counted, as the body it may have been


def test_a_stream_the_target_holds_open_does_not_hold_the_run(tmp_path, stub):
    """The channel closed; the target goes on, its stream open. The run ends after a grace,
    not the idle time, and the exchange is recorded as cut by the client, not complete."""
    request = b"GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n"
    release = threading.Event()

    class Holding(Stub):
        def _serve(self, connection):
            with connection:
                connection.recv(65536)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {}\n\n"
                )
                release.wait(10)  # the stream stays open: no length, no chunks, no close

    held = Holding(None)
    try:

        async def client(proxy):
            reader, writer = await proxy.front_connect()
            writer.write(request)
            await writer.drain()
            await asyncio.wait_for(reader.read(20), 5)
            writer.close()

        began = time.monotonic()
        _, events = asyncio.run(through(tmp_path, held.url, client))
        took = time.monotonic() - began
    finally:
        release.set()
        held.close()
    (ended,) = of(events, "http_end")
    assert ended["ended"] == "client_closed"
    assert events[-1]["type"] == "run_finished"
    assert took < 5


def test_connecting_to_the_target_has_the_step_timeout_and_is_unreachable(tmp_path):
    """A target that takes no connection (a full backlog drops the SYN): unreachable when the
    step timeout is over, not an initialize that went unanswered."""
    listener = socket.create_server(("127.0.0.1", 0), backlog=0)
    port = listener.getsockname()[1]
    fillers = []
    try:
        for _ in range(4):
            filler = socket.socket()
            filler.setblocking(False)
            with contextlib.suppress(BlockingIOError):
                filler.connect(("127.0.0.1", port))
            fillers.append(filler)
        began = time.monotonic()
        code, _, events = drive_http(
            tmp_path, f"http://127.0.0.1:{port}/mcp", "--step-timeout", "2"
        )
        took = time.monotonic() - began
    finally:
        for filler in fillers:
            filler.close()
        listener.close()
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == "http_unreachable"
    assert code == verdict.EXIT_SERVER_FAILED
    assert took < 9


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_answer_answers_the_request_of_its_own_exchange(tmp_path, stub, respond):
    """responded_method is what the exchange's request asked, not what an id matched: an
    answer with an id of its own is still the answer; a notification in the stream is none."""
    plain = reference_answer("")

    def answer(request: bytes) -> bytes:
        _, _, body = request.partition(b"\r\n\r\n")
        message = json.loads(body) if body else {}
        if message.get("method") != "tools/list":
            return plain(request)
        note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "x"}}
        reply = {"jsonrpc": "2.0", "id": "not-yours", "result": {"tools": []}}
        if respond == "json":
            data = json.dumps(reply).encode()
            return (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data)
                + data
            )
        stream = b"".join(b"data: " + json.dumps(m).encode() + b"\n\n" for m in (note, reply))
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n"
            + stream
        )

    _, _, events = drive_http(tmp_path, stub(answer).url, "--step-timeout", "2")
    requests = [
        e for e in of(events, "message")
        if e["direction"] == "client_to_server" and "tools/list" in json.dumps(e)
    ]  # fmt: skip
    (asked,) = {e["exchange"] for e in requests}
    answered = [
        e["responded_method"]
        for e in of(events, "message")
        if e["direction"] == "server_to_client" and e["exchange"] == asked
    ]
    assert answered == (["tools/list"] if respond == "json" else [None, "tools/list"])


@pytest.mark.parametrize(
    ("asked", "body"),
    [
        # A JSON body that is a request of the server's answers nothing.
        ("tools/list", {"jsonrpc": "2.0", "id": 7, "method": "sampling/createMessage"}),
        # An answer to a notification answers no request.
        ("notifications/initialized", {"jsonrpc": "2.0", "id": 1, "result": {}}),
    ],
)
def test_a_body_that_answers_no_request_has_no_responded_method(tmp_path, stub, asked, body):
    """Only an answer to a request names that request's method."""
    plain = reference_answer("")

    def answer(request: bytes) -> bytes:
        _, _, sent = request.partition(b"\r\n\r\n")
        if (json.loads(sent) if sent else {}).get("method") != asked:
            return plain(request)
        data = json.dumps(body).encode()
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data)
            + data
        )

    _, _, events = drive_http(tmp_path, stub(answer).url, "--step-timeout", "2")
    (exchange,) = {
        e["exchange"]
        for e in of(events, "message")
        if e["direction"] == "client_to_server" and asked in json.dumps(e)
    }
    (sent_back,) = [
        e
        for e in of(events, "message")
        if e["direction"] == "server_to_client" and e["exchange"] == exchange
    ]
    assert sent_back["responded_method"] is None


# -- 10. and 11. what is refused -------------------------------------------------------


def test_a_scenario_with_rules_is_refused_over_http_before_anything_starts(tmp_path, serve):
    server, url = serve()
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--http", url, "--scenario", "tool-poisoning", "--out-dir", str(out)]
    )
    assert code == cli.EXIT_REFUSED
    assert not out.exists() or not list(out.glob("*/events.jsonl"))
    assert server.behaviour.sessions == set()  # nothing reached the server


def test_a_scenario_without_rules_is_allowed_over_http(tmp_path, serve):
    _, url = serve()
    code, _, events = drive_http(tmp_path, url, "--scenario", str(ALL_SIGNALS))
    assert code == 0
    assert events[0]["authorization"]["rules_loaded"] is False


def test_http_proxy_refuses_an_engine_with_rules():
    from mcp_kymograph.engine import Engine
    from mcp_kymograph.rules import ToolPoisoning

    with pytest.raises(ValueError, match="rules"):
        HttpProxy(
            endpoint="http://127.0.0.1:1/mcp",
            recorder=None,
            limits=Limits(),
            engine=Engine([ToolPoisoning()]),
        )


@pytest.mark.parametrize(
    "extra",
    [
        ["--", sys.executable, "-c", "pass"],
        ["--manifest", "m.yaml"],
        ["--entry", "e"],
        ["--isolation", "host"],
    ],
)
def test_http_excludes_a_server_command_and_the_corpus_options(tmp_path, serve, capsys, extra):
    _, url = serve()
    out = tmp_path / "runs"
    code = cli.main(["drive", "--http", url, "--out-dir", str(out), *extra])
    assert code == cli.EXIT_REFUSED
    assert "--http" in capsys.readouterr().err
    assert not out.exists()


@pytest.mark.parametrize(
    "url",
    [
        "ftp://127.0.0.1:1/mcp",
        "http://127.0.0.1/mcp",
        "127.0.0.1:1",
        "http://127.0.0.1:1234/mcp@x",
        "http://127.0.0.1:1234/mcp%40x",
    ],
)
def test_http_refuses_a_url_it_cannot_drive(tmp_path, capsys, url):
    out = tmp_path / "runs"
    assert cli.main(["drive", "--http", url, "--out-dir", str(out)]) == cli.EXIT_REFUSED
    assert "--http" in capsys.readouterr().err
    assert not out.exists()


def test_the_engagement_gate_applies_to_http_as_to_stdio(tmp_path, serve):
    _, url = serve()
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--http", url, "--scenario", str(ALL_SIGNALS), "--target", "example.com",
         "--out-dir", str(out)]
    )  # fmt: skip
    assert code == cli.EXIT_REFUSED
    assert not out.exists()


def test_stdio_proxy_is_ready_when_it_has_a_child():
    """stdio: ready once there is a child; HTTP: always, there is none to wait for."""
    assert Proxy.ready.fget(SimpleNamespace(child_pid=None)) is False
    assert Proxy.ready.fget(SimpleNamespace(child_pid=4242)) is True
    assert HttpProxy.ready.fget(object()) is True


def test_http_proxy_refuses_an_endpoint_the_recording_would_refuse(tmp_path):
    """Not in the writer, after the run began: when the proxy is made."""
    with (
        Recorder.open(tmp_path / "e.jsonl", run_id="r", masker=Masker()) as recorder,
        pytest.raises(ValueError, match="@"),
    ):
        HttpProxy(
            endpoint="http://127.0.0.1:1/mcp@x",
            recorder=recorder,
            limits=Limits(),
            mode=Mode.DRIVER,
        )
