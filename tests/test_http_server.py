"""The HTTP test server (tests/fixtures/http_server.py), against itself only.

The client here is the least that speaks Streamable HTTP as 2025-06-18 has it, written for
these tests from the standard library; the tool's own driver is not involved.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import select
import selectors
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))
sys.path.insert(0, str(FIXTURES / "corpus"))

import http_server  # noqa: E402
import poison_server  # noqa: E402
import reference_server  # noqa: E402

ACCEPT = "application/json, text/event-stream"


class Client:
    """One connection per request, as simple as a client can be and still speak the transport."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.session: str | None = None
        self.next_id = 1

    def post(self, message: dict, *, headers: dict[str, str] | None = None):
        sent = {"Content-Type": "application/json", "Accept": ACCEPT}
        if self.session is not None:
            sent["Mcp-Session-Id"] = self.session
        sent.update(headers or {})
        return self._request("POST", json.dumps(message).encode(), sent)

    def request(self, method: str, params: dict | None = None, **options):
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.next_id += 1
        return self.post(message, **options)

    def initialize(self) -> dict:
        status, headers, body = self.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}},
        )
        assert status == 200
        self.session = headers["mcp-session-id"]
        return answer(headers, body)

    def _request(self, method: str, body: bytes | None, headers: dict[str, str]):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.request(method, http_server.PATH, body=body, headers=headers)
            response = connection.getresponse()
            try:
                data = response.read()
            except http.client.IncompleteRead as cut:
                data = cut.partial
            return response.status, {k.lower(): v for k, v in response.getheaders()}, data
        finally:
            connection.close()


def answer(headers: dict[str, str], body: bytes) -> dict:
    """The one JSON-RPC message of a response, as a JSON body or as one event."""
    if headers["content-type"] == "text/event-stream":
        assert body.endswith(b"\n\n"), "an event ends with a blank line"
        data = [line[len(b"data: ") :] for line in body.split(b"\n") if line.startswith(b"data: ")]
        assert len(data) == 1
        return json.loads(data[0])
    assert headers["content-type"] == "application/json"
    return json.loads(body)


@pytest.fixture
def start():
    servers = []

    def started(**behaviour) -> Client:
        server = http_server.serve(0, **behaviour)
        servers.append(server)
        return Client(server.server_address[1])

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


# -- the conversation -----------------------------------------------------------------------


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_a_discovery_conversation_goes_through(start, respond):
    client = start(respond=respond)
    hello = client.initialize()
    assert hello["result"]["serverInfo"]["name"] == "reference-server"
    assert hello["result"]["protocolVersion"] == "2025-06-18"
    status, _, body = client.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert (status, body) == (202, b"")
    status, headers, body = client.request("tools/list")
    assert status == 200
    assert headers["content-type"] == (
        "text/event-stream" if respond == "stream" else "application/json"
    )
    assert answer(headers, body)["result"]["tools"][0]["name"] == "tool_0"


@pytest.mark.parametrize(
    ("variant", "server", "description"),
    [
        ("reference", "reference-server", reference_server.DESCRIPTION),
        ("poison", "poison-server", poison_server.DESCRIPTION),
    ],
)
def test_it_describes_itself_as_the_stdio_pair_does(start, variant, server, description):
    client = start(variant=variant)
    assert client.initialize()["result"]["serverInfo"]["name"] == server
    status, headers, body = client.request("tools/list")
    tool = answer(headers, body)["result"]["tools"][0]
    assert tool["description"] == description


def test_its_answers_are_the_stdio_fixture_s_answers(start):
    client = start()
    hello = client.initialize()
    assert hello == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": http_server.discovery_server.build_capabilities(["tools"], None),
            "serverInfo": {"name": "reference-server", "version": "1"},
        },
    }
    status, headers, body = client.request("tools/list")
    expected = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": http_server.discovery_server.listing(
            "tools/list", 0, 1, reference_server.DESCRIPTION
        ),
    }
    assert answer(headers, body) == expected
    status, headers, body = client.request("no/such/method")
    assert answer(headers, body)["error"]["code"] == -32601


def test_a_response_from_the_client_is_accepted_without_a_body(start):
    client = start()
    client.initialize()
    status, _, body = client.post({"jsonrpc": "2.0", "id": 99, "result": {}})
    assert (status, body) == (202, b"")


@pytest.mark.parametrize("params", [[], None], ids=["list", "null"])
def test_params_that_are_not_an_object_still_get_the_first_page(start, params):
    client = start()
    client.initialize()
    status, headers, body = client.post(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": params}
    )
    assert status == 200
    assert answer(headers, body)["result"]["tools"][0]["name"] == "tool_0"


# -- sessions -------------------------------------------------------------------------------


def test_every_initialize_opens_its_own_session(start):
    first, second = start(), None
    first.initialize()
    second = Client(first.port)
    second.initialize()
    assert first.session != second.session
    sessions = set()
    for _ in range(20):
        other = Client(first.port)
        other.initialize()
        sessions.add(other.session)
    assert len(sessions) == 20
    assert all(len(session) == 32 and int(session, 16) >= 0 for session in sessions)
    # Not counted up: no two of them share their first half.
    assert len({session[:16] for session in sessions}) == 20


def test_without_a_session_the_answer_is_400(start):
    client = start()
    client.initialize()
    client.session = None
    status, _, body = client.request("tools/list")
    assert status == 400
    assert json.loads(body)["error"]["code"] == -32600


NOT_A_REQUEST = pytest.mark.parametrize(
    "message",
    [{"jsonrpc": "2.0", "method": "notifications/initialized"},
     {"jsonrpc": "2.0", "id": 9, "result": {}}],
    ids=["notification", "response"],
)  # fmt: skip


@NOT_A_REQUEST
def test_a_notification_or_response_without_a_session_is_400_too(start, message):
    client = start()
    client.initialize()
    client.session = None
    assert client.post(message)[0] == 400


def test_an_unknown_session_is_404(start):
    client = start()
    client.initialize()
    client.session = "0" * 32
    assert client.request("tools/list")[0] == 404


@NOT_A_REQUEST
def test_a_notification_or_response_in_an_unknown_session_is_404_too(start, message):
    client = start()
    client.initialize()
    client.session = "0" * 32
    assert client.post(message)[0] == 404


def test_a_deleted_session_is_unknown_afterwards(start):
    client = start()
    client.initialize()
    status, headers, _ = client._request("DELETE", None, {"Mcp-Session-Id": client.session})
    assert status == 204
    assert "content-length" not in headers  # a 204 carries none (RFC 9110, 8.6)
    assert client.request("tools/list")[0] == 404
    status, _, _ = client._request("DELETE", None, {"Mcp-Session-Id": client.session})
    assert status == 404


# -- what it refuses ------------------------------------------------------------------------


def test_get_opens_no_stream(start):
    client = start()
    status, headers, _ = client._request("GET", None, {"Accept": "text/event-stream"})
    assert (status, headers["allow"]) == (405, "POST, DELETE")


@pytest.mark.parametrize(
    "accept",
    ["application/json", "text/event-stream", "*/*", "application/json-seq, text/event-stream-x"],
)
def test_a_client_that_does_not_take_both_kinds_of_answer_is_refused(start, accept):
    client = start()
    assert client.request("initialize", {}, headers={"Accept": accept})[0] == 406


def test_accept_is_read_as_media_types_not_as_text(start):
    client = start()
    accept = "Application/JSON; charset=utf-8, TEXT/event-stream;q=0.5"
    assert client.request("initialize", {}, headers={"Accept": accept})[0] == 200


@pytest.mark.parametrize("origin", ["http://evil.example", "http://127.0.0.1:1", "null"])
def test_a_foreign_origin_is_refused(start, origin):
    client = start()
    assert client.request("initialize", {}, headers={"Origin": origin})[0] == 403


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_its_own_origin_is_accepted(start, host):
    client = start()
    origin = f"http://{host}:{client.port}"
    assert client.request("initialize", {}, headers={"Origin": origin})[0] == 200


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_origin_and_version_are_checked_on_every_method(start, method):
    client = start()
    client.initialize()
    session = {"Mcp-Session-Id": client.session}
    assert client._request(method, None, {**session, "Origin": "http://evil.example"})[0] == 403
    version = {**session, "MCP-Protocol-Version": "1999-01-01"}
    assert client._request(method, None, version)[0] == 400


def test_a_version_other_than_the_one_initialize_answers_with_is_400(start):
    """2025-03-26 too: it is what a missing header stands for, never what was negotiated."""
    client = start()
    client.initialize()
    for other in ("1999-01-01", "2025-03-26"):
        status, _, _ = client.request("tools/list", headers={"MCP-Protocol-Version": other})
        assert status == 400
    status, _, _ = client.request("tools/list", headers={"MCP-Protocol-Version": "2025-06-18"})
    assert status == 200


@pytest.mark.parametrize(
    ("body", "code"),
    [(b"not json", -32700), (b"[]", -32600),
     (b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]', -32600),
     (b'{"id":1,"method":"tools/list"}', -32600)],
    ids=["not json", "empty batch", "batch", "no jsonrpc"],
)  # fmt: skip
def test_a_body_that_is_not_one_message_is_400(start, body, code):
    """In a session, so that nothing else is what refuses it."""
    client = start()
    client.initialize()
    headers = {
        "Content-Type": "application/json",
        "Accept": ACCEPT,
        "Mcp-Session-Id": client.session,
    }
    status, _, answered = client._request("POST", body, headers)
    assert status == 400
    assert json.loads(answered)["error"]["code"] == code


def _headers_only(port: int, headers: dict[str, str]) -> int:
    """A POST that announces its body and sends none: the server answers from the headers."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.putrequest("POST", http_server.PATH)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        return connection.getresponse().status
    finally:
        connection.close()


def test_a_body_over_the_limit_is_413(start):
    client = start()
    headers = {"Accept": ACCEPT, "Content-Length": str(http_server.MAX_BODY_BYTES + 1)}
    assert _headers_only(client.port, headers) == 413


def test_a_body_at_the_limit_is_read(start):
    client = start()
    message = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    body = json.dumps(message).encode()
    body += b" " * (http_server.MAX_BODY_BYTES - len(body))
    status, _, _ = client._request("POST", body, {"Accept": ACCEPT})
    assert status == 200


def test_a_post_without_its_length_is_411(start):
    client = start()
    assert _headers_only(client.port, {"Accept": ACCEPT}) == 411


@pytest.mark.parametrize(
    "length",
    ["abc", "\u00b2", "-1", "1.0", ""],
    ids=["letters", "superscript two", "negative", "fraction", "empty"],
)
def test_a_length_that_is_not_a_decimal_number_is_400(start, length):
    client = start()
    assert _headers_only(client.port, {"Accept": ACCEPT, "Content-Length": length}) == 400


def test_a_length_of_thousands_of_digits_is_413(start):
    """More digits than int() takes from a string: refused, not a dropped connection."""
    client = start()
    assert _headers_only(client.port, {"Accept": ACCEPT, "Content-Length": "9" * 5000}) == 413


def test_a_length_with_thousands_of_leading_zeros_is_its_number(start):
    client = start()
    message = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    body = json.dumps(message).encode()
    headers = {"Accept": ACCEPT, "Content-Length": "0" * 5000 + str(len(body))}
    assert client._request("POST", body, headers)[0] == 200


def test_its_limits_are_the_ones_it_names():
    """The module's docstring says 1 MiB and ten seconds; the tests below read the constants."""
    assert http_server.MAX_BODY_BYTES == 1024 * 1024
    assert http_server.Handler.timeout == 10


#: What is left of a refused POST's body, written as a request of its own.
LEFTOVER = b"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"


@pytest.mark.parametrize(
    ("header", "status"),
    [("Accept: application/json", 406),
     (f"Accept: {ACCEPT}\r\nMCP-Protocol-Version: 1999-01-01", 400)],
    ids=["refused without a body", "refused with a body"],
)  # fmt: skip
def test_after_a_refusal_the_connection_ends(start, header, status):
    """The body a refusal did not read is never read as the next request."""
    client = start()
    head = (
        f"POST {http_server.PATH} HTTP/1.1\r\nHost: 127.0.0.1\r\n{header}\r\n"
        f"Content-Length: {len(LEFTOVER)}\r\n\r\n"
    )
    received = b""
    with socket.create_connection(("127.0.0.1", client.port), timeout=10) as connection:
        connection.sendall(head.encode() + LEFTOVER)  # in one piece, so it is read in one
        while chunk := connection.recv(65536):
            received += chunk
    assert received.startswith(f"HTTP/1.1 {status} ".encode())
    assert received.count(b"HTTP/1.1 ") == 1


#: A POST that passes every check on its headers and then sends one byte of the ten it names.
HALF_A_BODY = (
    f"POST {http_server.PATH} HTTP/1.1\r\nAccept: {ACCEPT}\r\nContent-Length: 10\r\n\r\n{{"
).encode()


@pytest.mark.parametrize("sent", [b"", HALF_A_BODY], ids=["idle", "half a body"])
def test_a_connection_that_stalls_is_closed(start, monkeypatch, sent):
    """With the idle limit at a fiftieth of how long the client waits for the close."""
    monkeypatch.setattr(http_server.Handler, "timeout", 0.2)
    client = start()
    with socket.create_connection(("127.0.0.1", client.port), timeout=10) as connection:
        connection.sendall(sent)
        assert connection.recv(65536) == b""


@pytest.mark.parametrize(
    "message",
    [{"jsonrpc": "2.0"}, {"jsonrpc": "2.0", "id": 7}, {"jsonrpc": "2.0", "id": True, "result": {}},
     {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}}, {"jsonrpc": "2.0", "method": 3},
     {"jsonrpc": "2.0", "id": None, "method": "tools/list"},
     {"jsonrpc": "2.0", "id": 1.5, "method": "tools/list"}],
    ids=["empty", "id only", "bool id", "result and error", "method not a string", "null id",
         "fractional id"],
)  # fmt: skip
def test_what_is_neither_request_notification_nor_response_is_400(start, message):
    client = start()
    client.initialize()
    status, _, body = client.post(message)
    assert status == 400
    assert json.loads(body)["error"]["code"] == -32600


def test_nesting_too_deep_to_parse_is_a_parse_error(start):
    client = start()
    status, _, body = client._request("POST", b"[" * 200_000, {"Accept": ACCEPT})
    assert status == 400
    assert json.loads(body)["error"]["code"] == -32700


def test_another_path_is_404(start):
    client = start()
    connection = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    connection.request("POST", "/other", body=b"{}", headers={"Accept": ACCEPT})
    assert connection.getresponse().status == 404
    connection.close()


# -- where it listens -----------------------------------------------------------------------


def test_it_listens_on_the_loopback_address_only():
    server = http_server.serve(0)
    try:
        assert server.socket.family == socket.AF_INET
        assert server.socket.getsockname()[0] == "127.0.0.1"
    finally:
        server.shutdown()
        server.server_close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@contextlib.contextmanager
def _program(*arguments: str):
    """The server as its own process; yields the address it names, then stops it."""
    process = subprocess.Popen(  # noqa: S603 - our own fixture, by path
        [sys.executable, str(FIXTURES / "http_server.py"), *arguments],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        ready, _, _ = select.select([process.stdout], [], [], 10)
        assert ready, "the server named no address within ten seconds"
        yield process.stdout.readline().strip()
    finally:
        process.terminate()
        process.wait(timeout=10)


def test_run_as_a_program_it_names_its_address_and_takes_a_free_port():
    with _program("--port", "0") as address:
        assert address.startswith("http://127.0.0.1:")
        assert address.endswith("/mcp")
        port = int(address.split(":")[2].split("/")[0])
        assert port > 0
        assert Client(port).initialize()["result"]["serverInfo"]["name"] == "reference-server"


def test_run_as_a_program_it_takes_the_port_it_is_given():
    port = _free_port()
    with _program("--port", str(port)) as address:
        assert address == f"http://127.0.0.1:{port}/mcp"
        assert Client(port).initialize()["result"]["serverInfo"]["name"] == "reference-server"


def test_serve_takes_the_port_it_is_given():
    port = _free_port()
    server = http_server.serve(port)
    try:
        assert server.server_address == ("127.0.0.1", port)
    finally:
        server.shutdown()
        server.server_close()


def test_run_as_a_program_it_takes_variant_respond_and_failure():
    port = _free_port()
    arguments = ("--variant", "poison", "--respond", "stream", "--failure", "wrong-status")
    with _program("--port", str(port), *arguments):
        client = Client(port)
        assert client.initialize()["result"]["serverInfo"]["name"] == "poison-server"
        status, headers, body = client.request("tools/list")
        assert (status, headers["content-type"]) == (418, "text/event-stream")
        tool = answer(headers, body)["result"]["tools"][0]
        assert tool["description"] == poison_server.DESCRIPTION


def test_run_as_a_program_it_takes_the_failing_method():
    port = _free_port()
    arguments = ("--failure", "wrong-status", "--failure-method", "resources/list")
    with _program("--port", str(port), *arguments):
        client = Client(port)
        client.initialize()
        assert client.request("tools/list")[0] == 200
        assert client.request("resources/list")[0] == 418


def test_run_as_a_program_it_takes_the_oversized_length():
    port = _free_port()
    with _program("--port", str(port), "--failure", "oversized", "--oversized-bytes", "7"):
        client = Client(port)
        client.initialize()
        _, headers, body = client.request("tools/list")
        description = answer(headers, body)["result"]["tools"][0]["description"]
        assert description == reference_server.DESCRIPTION + " xxxxxxx"


@pytest.mark.parametrize(
    "arguments",
    [("--failure", "oversized", "--failure-method", "resources/list"),
     ("--oversized-bytes", "-1")],
    ids=["oversized elsewhere", "negative length"],
)  # fmt: skip
def test_run_as_a_program_it_refuses_what_it_cannot_do_as_a_usage_error(arguments):
    done = subprocess.run(  # noqa: S603 - our own fixture, by path
        [sys.executable, str(FIXTURES / "http_server.py"), *arguments],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 2
    assert "error:" in done.stderr
    assert "Traceback" not in done.stderr


# -- how it stops ----------------------------------------------------------------------------


class _Readable(selectors.PollSelector):
    """The poll of ``serve_forever``, saying the listening socket is readable whether or not a
    connection is there: the accept() after it then finds none. ``polled`` is set once the loop
    has asked."""

    polled = threading.Event()

    def select(self, timeout=None):  # noqa: ARG002 - always at once
        _Readable.polled.set()
        return [(key, selectors.EVENT_READ) for key in self.get_map().values()]


def test_an_accept_that_finds_no_connection_does_not_hold_up_shutdown(monkeypatch):
    """socketserver accepts only after its poll, and a blocking accept() with no connection there
    would wait for the next client, and shutdown() with it: for good, when none comes."""
    _Readable.polled.clear()
    monkeypatch.setattr(socketserver, "_ServerSelector", _Readable)
    server = http_server.serve(0)
    stopping = threading.Thread(target=server.shutdown, daemon=True)
    try:
        assert _Readable.polled.wait(5)
        time.sleep(0.2)  # into the accept() that finds nothing
        stopping.start()
        stopping.join(5)
        stopped = not stopping.is_alive()
    finally:
        # The loop ends whatever happened above: left running, it would spin on a poll that is
        # always ready for the rest of the suite. A loop that has not started yet sees the
        # shutdown request when it does, and ends at once.
        if stopping.ident is None:
            stopping.start()
            stopping.join(5)
        if stopping.is_alive():  # a connection for the waiting accept(), so that the test ends
            socket.create_connection(server.server_address, timeout=5).close()
            stopping.join(5)
        server.server_close()
    assert stopped, "shutdown() still waits on an accept() that has nothing to accept"


@pytest.mark.parametrize("tls", [False, True], ids=["http", "https"])
def test_the_connection_it_accepts_has_no_timeout_of_the_listening_socket(tls):
    """The bound is on the accept() alone: what the handler reads and writes waits as before."""
    certificate = (str(FIXTURES / "tls" / "localhost.pem"), str(FIXTURES / "tls" / "localhost.key"))
    server = http_server._Server(0, http_server.Behaviour(), tls=certificate if tls else None)
    try:
        with socket.create_connection(server.server_address, timeout=5):
            connection, _ = server.get_request()
            with connection:
                assert connection.gettimeout() is None
        assert server.socket.gettimeout() == http_server.ACCEPT_SECONDS
    finally:
        server.server_close()


# -- the failures it can be asked for -------------------------------------------------------


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_wrong_status(start, respond):
    client = start(respond=respond, failure="wrong-status")
    client.initialize()
    status, headers, body = client.request("tools/list")
    assert status == 418
    assert answer(headers, body)["result"]["tools"]


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_aborted_stream_ends_mid_answer(start, monkeypatch, respond):
    # Idle limit past the client's own: a server that left the connection open would fail
    # this test with a timeout instead of passing it once the idle limit closed it.
    monkeypatch.setattr(http_server.Handler, "timeout", 60)
    client = start(respond=respond, failure="aborted-stream")
    client.initialize()
    status, headers, body = client.request("tools/list")
    assert status == 200
    if respond == "json":
        assert len(body) < int(headers["content-length"])
        with pytest.raises(ValueError):
            json.loads(body)
    else:
        # Cut inside the event's data: not even its line ends.
        assert body.startswith(b"event: message\ndata: {")
        assert not body.endswith(b"\n")


def test_a_missing_end_of_event(start):
    client = start(respond="stream", failure="missing-end")
    client.initialize()
    _, headers, body = client.request("tools/list")
    assert body.endswith(b"}\n")
    assert not body.endswith(b"\n\n")


def test_a_missing_end_of_document(start):
    client = start(failure="missing-end")
    client.initialize()
    _, headers, body = client.request("tools/list")
    assert len(body) == int(headers["content-length"])
    with pytest.raises(ValueError):
        json.loads(body)


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_an_oversized_answer_is_whole_and_over_the_message_limit(start, respond):
    client = start(respond=respond, failure="oversized", oversized_bytes=1_500_000)
    client.initialize()
    _, headers, body = client.request("tools/list")
    assert len(body) > 1024 * 1024
    description = answer(headers, body)["result"]["tools"][0]["description"]
    assert description == reference_server.DESCRIPTION + " " + "x" * 1_500_000


@pytest.mark.parametrize(
    "behaviour",
    [{"variant": "nope"}, {"respond": "sse"}, {"failure": "aborted_stream"},
     {"oversized_bytes": -1},
     {"failure": "wrong-status", "failure_method": "notifications/initialized"},
     {"failure": "oversized", "failure_method": "resources/list"}],
    ids=["variant", "respond", "failure", "negative length", "a notification fails",
         "oversized elsewhere"],
)  # fmt: skip
def test_what_it_cannot_do_is_refused_when_it_starts(behaviour):
    with pytest.raises(ValueError):
        http_server.Behaviour(**behaviour)


@pytest.mark.parametrize(
    "failure",
    [f for f in http_server.FAILURES if f not in ("oversized", "no-session-id")],
)  # no-session-id is the handshake's, tested on its own below
def test_a_failure_touches_only_its_method(start, failure):
    client = start(failure=failure, failure_method="resources/list")
    client.initialize()
    status, headers, body = client.request("tools/list")
    assert status == 200
    assert (
        answer(headers, body)["result"]["tools"][0]["description"] == reference_server.DESCRIPTION
    )


# -- the host, the two later failures, the two stricter refusals ---------------------------


def test_serve_takes_the_host_it_is_given():
    server = http_server.serve(0, host="127.0.0.2")
    try:
        assert server.server_address[0] == "127.0.0.2"
    finally:
        server.shutdown()
        server.server_close()


def test_run_as_a_program_it_takes_the_host_and_names_it():
    with _program("--host", "127.0.0.2") as address:
        assert address.startswith("http://127.0.0.2:")


def test_no_session_id_leaves_it_out_of_the_answer_and_still_asks_for_it(start):
    client = start(failure="no-session-id")
    status, headers, _ = client.request(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}},
    )
    assert status == 200
    assert "mcp-session-id" not in headers
    assert client.request("tools/list")[0] == 400


def test_session_lost_answers_its_method_404_and_no_other(start):
    client = start(failure="session-lost", failure_method="resources/list")
    client.initialize()
    assert client.request("tools/list")[0] == 200
    assert client.request("resources/list")[0] == 404
    assert client.post({"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == 202


def test_session_lost_cannot_be_the_handshake():
    with pytest.raises(ValueError):
        http_server.Behaviour(failure="session-lost", failure_method="initialize")


INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode()


def _raw(port: int, fields: str, body: bytes) -> bytes:
    """One POST with the given header fields, as sent; everything the server answers."""
    received = b""
    head = f"POST {http_server.PATH} HTTP/1.1\r\nHost: x\r\nAccept: {ACCEPT}\r\n{fields}\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(head.encode() + body)
        while chunk := connection.recv(65536):
            received += chunk
    return received


def test_transfer_encoding_together_with_content_length_is_400_and_ends_the_connection(start):
    client = start()
    fields = f"Transfer-Encoding: chunked\r\nContent-Length: {len(INITIALIZE)}\r\n"
    received = _raw(client.port, fields, INITIALIZE)
    assert received.startswith(b"HTTP/1.1 400 ")
    assert received.count(b"HTTP/1.1 ") == 1


def test_two_content_lengths_that_differ_are_400_and_end_the_connection(start):
    client = start()
    fields = f"Content-Length: {len(INITIALIZE)}\r\nContent-Length: {len(INITIALIZE) + 5}\r\n"
    received = _raw(client.port, fields, INITIALIZE + b"POST / HTTP/1.1\r\n\r\n")
    assert received.startswith(b"HTTP/1.1 400 ")
    assert received.count(b"HTTP/1.1 ") == 1


def test_two_content_lengths_that_agree_are_one(start):
    client = start()
    length = f"Content-Length: {len(INITIALIZE)}\r\n"
    fields = length + length + "Connection: close\r\n"
    assert _raw(client.port, fields, INITIALIZE).startswith(b"HTTP/1.1 200 ")
