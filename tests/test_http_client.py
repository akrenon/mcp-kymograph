"""The driver's channel over Streamable HTTP (src/mcp_kymograph/http_client.py).

Against the test server (tests/fixtures/http_server.py) where it behaves, and against small
stubs where a test needs the bytes to be something else, or needs to see what was sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_kymograph.driver import DISCOVERY, OVERSIZED, Driver
from mcp_kymograph.events import (
    HTTP_SSE_ONLY,
    HTTP_STATUS,
    HTTP_UNREACHABLE,
    PARTIAL_REASONS,
    SESSION_LOST,
    UNREADABLE,
)
from mcp_kymograph.http_client import HttpClientChannel
from mcp_kymograph.http_client import _parse_url as parse_url

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(FIXTURES / "corpus"))

import http_server  # noqa: E402
import poison_server  # noqa: E402

STEP_TIMEOUT = 5.0


@pytest.fixture
def start():
    servers = []

    def started(**behaviour):
        server = http_server.serve(0, **behaviour)
        servers.append(server)
        return server, f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


@dataclass
class Run:
    outcome: object
    failed: list
    skipped: list
    unanswered: list
    finished: list
    channel: HttpClientChannel


def drive(url: str, **options) -> Run:
    """The discovery script into an HttpClientChannel, with what the driver recorded."""
    failed, skipped, unanswered, finished = [], [], [], []

    async def record(into, **fields) -> None:
        into.append(fields)

    channel = HttpClientChannel(url, **options)
    driver = Driver(
        DISCOVERY,
        channel,
        record_skipped=lambda **f: record(skipped, **f),
        record_failed=lambda **f: record(failed, **f),
        record_unanswered=lambda **f: record(unanswered, **f),
        record_finished=lambda **f: record(finished, **f),
        step_timeout=STEP_TIMEOUT,
    )
    outcome = asyncio.run(driver.run())
    return Run(outcome, failed, skipped, unanswered, finished, channel)


def reasons(run: Run) -> list[str]:
    return [reason for _, _, reason, _ in run.outcome.unanswered]


# -- a stub that keeps what it was sent -----------------------------------------------------


@dataclass
class Seen:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes


def http(
    status: int, body: bytes = b"", *, kind: str = "application/json", extra: str = ""
) -> bytes:
    head = f"HTTP/1.1 {status} X\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
    if body:
        head += f"Content-Type: {kind}\r\n"
    return (head + extra + "\r\n").encode() + body


class Stub:
    """One thread per connection; ``reply(connection, seen)`` writes the answer."""

    def __init__(self, reply) -> None:
        self._seen: dict[int, Seen] = {}  # by the number ``_accept`` gave the connection
        self._reply = reply
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._listener.getsockname()[1]}/mcp"
        # A timeout, so that the thread notices ``close`` and ends: closing the socket does not
        # wake a thread blocked in its accept(), which would wait there for good.
        self._listener.settimeout(http_server.ACCEPT_SECONDS)
        self._closed = False
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    @property
    def requests(self) -> list[Seen]:
        """The requests read so far, in the order their connections were accepted: the client
        sends one after the other, but the threads that read them finish in any order."""
        return [self._seen[number] for number in sorted(self._seen)]

    def _accept(self) -> None:
        number = 0
        while not self._closed:
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection, number), daemon=True).start()
            number += 1

    def _serve(self, connection: socket.socket, number: int) -> None:
        with connection:
            connection.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ")
            headers = {k.lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
            while len(body) < int(headers.get("content-length", 0)):
                body += connection.recv(65536)
            seen = Seen(method, target, headers, body)
            self._seen[number] = seen
            with contextlib.suppress(OSError):
                self._reply(connection, seen)

    def close(self) -> None:
        self._closed = True
        self._acceptor.join(5)
        self._listener.close()


@pytest.fixture
def stub():
    stubs = []

    def made(reply) -> Stub:
        stubs.append(Stub(reply))
        return stubs[-1]

    yield made
    for each in stubs:
        each.close()


def in_accept(thread: threading.Thread) -> bool:
    """Whether ``thread`` stands in a socket's accept() right now: a stub closed before its
    thread got there would end without ever waiting in one, and prove nothing."""
    frame = sys._current_frames().get(thread.ident)
    while frame is not None:
        if frame.f_code.co_name == "accept" and frame.f_code.co_filename == socket.__file__:
            return True
        frame = frame.f_back
    return False


def test_a_closed_stub_leaves_no_thread_behind_and_closes_at_once():
    """Its accept() would otherwise wait for good on the closed socket, and ``close`` would wait
    out its join of 5 s for it: closing does not wake it."""
    before = set(threading.enumerate())
    stub = Stub(lambda connection, seen: None)  # nothing connects
    deadline = time.monotonic() + 5
    while not in_accept(stub._acceptor) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert in_accept(stub._acceptor), "the stub's thread never reached its accept()"
    started = time.monotonic()
    stub.close()
    took = time.monotonic() - started
    deadline = time.monotonic() + 5
    while (left := set(threading.enumerate()) - before) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert left == set()
    assert took < 1, f"close() took {took:.2f} s"


# -- discovery against the test server ------------------------------------------------------


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_discovery_is_answered_in_a_session_that_delete_ends(start, respond):
    """Every step answered and the inventory complete; the session was used and then deleted."""
    server, url = start(respond=respond)
    run = drive(url)
    assert run.outcome.server_failed is None
    assert run.outcome.inventory == "complete"
    assert run.outcome.sent == ("initialize", "notifications/initialized", "tools/list")
    assert server.behaviour.sessions == set()  # made by initialize, ended by DELETE
    assert run.channel.failure is None


def test_the_description_with_the_payload_arrives_as_a_line(start):
    """The poison server's tool description is in the line the driver reads."""
    _, url = start(variant="poison")

    async def converse() -> bytes:
        channel = HttpClientChannel(url)
        await channel.send(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n')
        assert await channel.read_line(STEP_TIMEOUT)
        await channel.send(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        await channel.send(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
        line = await channel.read_line(STEP_TIMEOUT)
        channel.close()
        return line

    line = asyncio.run(converse())
    assert poison_server.DESCRIPTION in json.loads(line)["result"]["tools"][0]["description"]


def test_a_wrong_status_is_the_reason_of_the_step_and_of_the_rest(start):
    """418 on tools/list: unanswered with http_status, nothing else sent, the inventory partial."""
    _, url = start(failure="wrong-status")
    run = drive(url)
    assert run.outcome.unanswered == (("tools/list", 0, HTTP_STATUS, ""),)
    assert {reason for _, reason in run.outcome.skipped} == {HTTP_STATUS}
    assert run.outcome.inventory == "partial"


def test_a_session_the_server_lost_is_session_lost(start):
    """404 on a request that carried a session."""
    _, url = start(failure="session-lost")
    run = drive(url)
    assert reasons(run) == [SESSION_LOST]
    assert run.outcome.inventory == "partial"


def test_a_missing_session_id_is_answered_400_and_is_http_status(start):
    """initialize gave no id; the server wants one from then on, and says 400."""
    server, url = start(failure="no-session-id")
    run = drive(url)
    assert reasons(run) == [HTTP_STATUS]
    assert run.channel.failure is None or run.channel.failure == HTTP_STATUS
    assert server.behaviour.sessions  # nobody had the id to end it with


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_answer_cut_short_is_unreadable(start, respond):
    """The connection ended inside the answer."""
    _, url = start(respond=respond, failure="aborted-stream")
    assert reasons(drive(url)) == [UNREADABLE]


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_answer_without_its_end_is_unreadable(start, respond):
    """The document lacks its last character, or the event its blank line."""
    _, url = start(respond=respond, failure="missing-end")
    assert reasons(drive(url)) == [UNREADABLE]


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_answer_over_the_message_limit_is_unreadable(start, respond):
    """A tool description of 2 MiB against a limit of 1 MiB; nothing of it is held."""
    _, url = start(respond=respond, failure="oversized")
    assert reasons(drive(url)) == [UNREADABLE]


def test_no_server_at_the_port_is_http_unreachable():
    """The handshake itself failed, and says why."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    run = drive(f"http://127.0.0.1:{port}/mcp")
    assert run.outcome.server_failed == HTTP_UNREACHABLE
    assert [entry["reason"] for entry in run.failed] == [HTTP_UNREACHABLE]
    assert run.outcome.inventory == "none"


# -- the old transport, and what is sent ----------------------------------------------------


def test_an_endpoint_that_speaks_only_the_old_transport_is_named_and_not_followed(stub):
    """POST is 405, GET opens a stream whose first event is endpoint: http_sse_only."""
    event = b"event: endpoint\ndata: /elsewhere/messages?sessionId=1\n\n"

    def reply(connection, seen):
        if seen.method == "POST":
            connection.sendall(http(405))
        else:
            connection.sendall(http(200, event, kind="text/event-stream"))

    server = stub(reply)
    run = drive(server.url)
    assert run.outcome.server_failed == HTTP_SSE_ONLY
    assert [(seen.method, seen.target) for seen in server.requests] == [
        ("POST", "/mcp"),
        ("GET", "/mcp"),
    ]
    assert server.requests[1].headers["accept"] == "text/event-stream"


def test_a_405_without_a_stream_is_only_http_status(stub):
    """The probe finds no endpoint event, so the status stays the reason."""

    def reply(connection, seen):
        connection.sendall(http(405))

    run = drive(stub(reply).url)
    assert run.outcome.server_failed == HTTP_STATUS


def test_the_heads_of_the_requests(stub):
    """Both types accepted, JSON content, one exchange per connection, no Origin, and the
    protocol version only from the second request on, as the server named it."""
    hello = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"protocolVersion": "2025-03-26", "capabilities": {}},
    }

    def reply(connection, seen):
        if seen.method == "POST" and json.loads(seen.body).get("method") == "initialize":
            connection.sendall(
                http(200, json.dumps(hello).encode(), extra="Mcp-Session-Id: s-1\r\n")
            )
        elif seen.method == "POST":
            connection.sendall(http(202))
        else:
            connection.sendall(http(204))

    server = stub(reply)
    run = drive(server.url)
    assert run.outcome.inventory == "complete"
    first, second, last = server.requests
    assert [seen.method for seen in server.requests] == ["POST", "POST", "DELETE"]
    for seen in (first, second):
        assert seen.headers["accept"] == "application/json, text/event-stream"
        assert seen.headers["content-type"] == "application/json"
        assert seen.headers["content-length"] == str(len(seen.body))
    for seen in server.requests:
        assert seen.headers["connection"] == "close"
        assert seen.headers["host"] == server.url.split("/")[2]
        assert "origin" not in seen.headers
        assert "authorization" not in seen.headers
    assert "mcp-protocol-version" not in first.headers
    assert "mcp-session-id" not in first.headers
    # The version the server answered with, not the one the driver asked for (2025-06-18).
    assert second.headers["mcp-protocol-version"] == "2025-03-26"
    assert second.headers["mcp-session-id"] == "s-1"
    assert last.headers["mcp-session-id"] == "s-1"


def test_a_head_without_end_is_read_to_a_bound(stub):
    """A head that never ends: unreadable (or no answer) at the step's end, the channel
    holding less than twice the head limit."""

    def reply(connection, seen):
        connection.sendall(b"HTTP/1.1 200 OK\r\n")
        for _ in range(512):
            connection.sendall(b"X-Fill: " + b"a" * 8000 + b"\r\n")

    server = stub(reply)
    run = drive(server.url)
    assert [entry["reason"] for entry in run.failed][0] in (UNREADABLE, "no_answer")
    assert run.channel.peak_buffered_bytes < 2 * 64 * 1024


def test_the_partial_reasons_include_the_http_ones():
    """A step skipped for an HTTP reason leaves the inventory partial."""
    assert {HTTP_STATUS, SESSION_LOST, HTTP_UNREACHABLE, HTTP_SSE_ONLY} <= PARTIAL_REASONS


# -- the channel on its own -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://127.0.0.1/mcp", "http://127.0.0.1/mcp", "http://127.0.0.1:1",
     "http://:1/mcp", "http://u:p@127.0.0.1:1/mcp", "http://127.0.0.1:1/mcp#x",
     "http://127.0.0.1:1/m cp", "ftp://127.0.0.1:1/mcp", "http://127.0.0.1:99999/mcp",
     "http://127.0.0.1:1/mcp\r\nX: y"],
)  # fmt: skip
def test_a_url_that_is_not_http_with_host_port_and_path_is_refused(url):
    with pytest.raises(ValueError):
        HttpClientChannel(url)


def test_the_target_keeps_the_query():
    assert parse_url("http://example.test:8080/mcp?a=1") == (
        "http", "example.test", 8080, "/mcp?a=1"
    )  # fmt: skip


def test_a_closed_channel_refuses_to_send_and_closes_again():
    async def attempt() -> None:
        channel = HttpClientChannel("http://127.0.0.1:1/mcp")
        channel.close_write()
        channel.close()
        channel.close()
        with pytest.raises(ConnectionError):
            await channel.send(b"{}\n")

    asyncio.run(attempt())


def test_a_session_id_that_cannot_be_sent_back_is_no_session_and_is_noticed(stub):
    """A space in it; the notice does not repeat it."""
    notices = []

    def reply(connection, seen):
        body = b'{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}'
        connection.sendall(http(200, body, extra="Mcp-Session-Id: not ok\r\n"))

    server = stub(reply)
    run = drive(server.url, notice=notices.append)
    assert run.outcome.inventory == "complete"
    assert len(notices) == 1 and "not ok" not in notices[0]
    assert all("mcp-session-id" not in seen.headers for seen in server.requests)
    assert all(seen.method != "DELETE" for seen in server.requests)


def test_an_unreadable_body_is_the_sentinel_and_then_the_end(stub):
    """200 with a type that is neither JSON nor a stream, and a body."""

    def reply(connection, seen):
        connection.sendall(http(200, b"<html>", kind="text/html"))

    async def converse():
        channel = HttpClientChannel(stub(reply).url)
        await channel.send(b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n')
        first = await channel.read_line(STEP_TIMEOUT)
        second = await channel.read_line(STEP_TIMEOUT)
        channel.close()
        return first, second

    assert asyncio.run(converse()) == (OVERSIZED, None)


def test_an_event_stream_cut_between_events_is_unreadable(stub):
    """A stream framed by a length that ends after a whole notification and before the
    answer: the answer may have been in what never came, so the step is answer_unreadable."""
    note = b'data: {"jsonrpc":"2.0","method":"notifications/message","params":{}}\n\n'

    def reply(connection, seen):
        message = json.loads(seen.body) if seen.body else {}
        method = message.get("method")
        if method == "initialize":
            hello = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}},
            }
            connection.sendall(http(200, json.dumps(hello).encode()))
        elif method == "tools/list":
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                + b"Content-Length: %d\r\n\r\n" % (len(note) + 500)
                + note
            )
        else:
            connection.sendall(http(202))

    assert reasons(drive(stub(reply).url)) == [UNREADABLE]
