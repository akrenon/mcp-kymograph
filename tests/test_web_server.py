"""The web interface's server: routing, every refusal, the headers and the static allowlist.

In process, on a loopback address and a free port, against a stand-in for ``views`` and a static
directory of the test's own: the server is tested for what it decides — who may ask, for what,
with which parameters — never for what a view says. Every request but the ones that test the
session carries the cookie the token was exchanged for (:func:`ask`).
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import socket
import threading
from http import HTTPStatus
from importlib import resources
from pathlib import Path

import pytest

from mcp_kymograph.authorization import LOCAL_TARGETS, LOOPBACK_LITERALS
from mcp_kymograph.web import server as web
from mcp_kymograph.web.views import Download, Sources, ViewError

OUTSIDE = "OUTSIDE-the-static-directory-0123456789"
TRACE_MARK = "TRACE-MARK-never-in-an-answer"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
EXPECTED_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


# -- the stand-in and the server ---------------------------------------------------------


class StandIn:
    """Every view function of the contract; each records its call and answers with it."""

    FUNCTIONS = (
        "about", "runs", "run", "messages", "message", "store_runs", "store_findings",
        "store_candidates", "store_diff", "fleets", "fleet", "fleet_compare", "corpora", "corpus",
        "scenarios", "scenario", "signals", "store_engagement", "triage", "triage_history",
        "triage_review", "bundles", "bundle", "bundle_file", "attestations", "attestation",
        "attestation_file",
    )  # fmt: skip
    #: The functions that answer with a file to download, not an envelope.
    DOWNLOADS = ("bundle_file", "attestation_file")

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.behaviour: dict[str, object] = {}
        for name in self.FUNCTIONS:
            setattr(self, name, self._function(name))

    def _function(self, name: str):
        def view(sources, *arguments):
            assert isinstance(sources, Sources)
            self.calls.append((name, arguments))
            behaviour = self.behaviour.get(name)
            if isinstance(behaviour, BaseException):
                raise behaviour
            if callable(behaviour):
                return behaviour()
            if name in self.DOWNLOADS:
                return Download(f"{name}.bin", json.dumps(list(arguments)).encode())
            return {"view": name, "notices": [], "data": {"arguments": list(arguments)}}

        return view


@pytest.fixture
def static_dir(tmp_path: Path) -> Path:
    (tmp_path / "secret.txt").write_text(OUTSIDE)
    (tmp_path / "secret.css").write_text(OUTSIDE)
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text("<!doctype html><title>index</title>")
    (static / "app.css").write_text("body { color: black; }")
    (static / "app.js").write_text("'use strict';")
    (static / "mark.svg").write_text("<svg></svg>")
    (static / "font.woff2").write_bytes(b"wOF2\x00")
    (static / "image.png").write_bytes(b"\x89PNG\r\n")
    # Not served: a hidden file, a suffix outside the map, a name with a space, a directory and
    # what is in it, a symbolic link to a file outside.
    (static / ".hidden.css").write_text(OUTSIDE)
    (static / "notes.txt").write_text(OUTSIDE)
    (static / "notes.json").write_text(OUTSIDE)
    (static / "with space.css").write_text(OUTSIDE)
    (static / "sub").mkdir()
    (static / "sub" / "inner.css").write_text(OUTSIDE)
    (static / "link.css").symlink_to(tmp_path / "secret.css")
    return static


def serve(views, static, bind="127.0.0.1"):
    server = web.make_server(Sources(), bind, 0, views=views, static=static)
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def stand_in() -> StandIn:
    return StandIn()


@pytest.fixture
def server(stand_in, static_dir):
    running, thread = serve(stand_in, static_dir)
    yield running
    running.shutdown()
    running.server_close()
    thread.join(timeout=10)


class Answer:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.status = status
        self.header_list = headers
        self.headers = {name.lower(): value for name, value in headers}
        self.body = body

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def json(self):
        return json.loads(self.body)


def own_host(server) -> str:
    return f"127.0.0.1:{server.port}"


def session_cookie(server) -> str:
    return f"{server.cookie_name}={server.session}"


def ask(server, target, *, method="GET", host="own", origin=None, extra=(), cookie="session"):
    """One request through http.client with the Host (and Origin) set by the test, and the
    session cookie: ``cookie`` is ``"session"`` for the server's own, ``None`` for no Cookie
    header, or the header's value."""
    connection = http.client.HTTPConnection(str(server.address), server.port, timeout=10)
    try:
        connection.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        if host is not None:
            connection.putheader("Host", own_host(server) if host == "own" else host)
        if origin is not None:
            connection.putheader("Origin", origin)
        if cookie is not None:
            connection.putheader(
                "Cookie", session_cookie(server) if cookie == "session" else cookie
            )
        for name, value in extra:
            connection.putheader(name, value)
        connection.endheaders()
        response = connection.getresponse()
        body = response.read()
        return Answer(response.status, response.getheaders(), body)
    finally:
        connection.close()


def ask_raw(server, raw: bytes) -> bytes:
    """Bytes in, whatever comes back out: for request lines http.client would not send."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect((str(server.address), server.port))
        connection.sendall(raw)
        chunks = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def parse_raw(answer: bytes) -> Answer:
    head, _, body = answer.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = [tuple(part.strip() for part in line.split(":", 1)) for line in lines[1:]]
    return Answer(status, headers, body)


def assert_headers(answer: Answer) -> None:
    for name, value in EXPECTED_HEADERS.items():
        assert answer.header(name) == value, (name, answer.header_list)
    assert not [name for name, _ in answer.header_list if name.lower().startswith("access-")], (
        "no CORS header, ever"
    )


def assert_error(answer: Answer, status: int, kind: str) -> dict:
    assert answer.status == status, (answer.status, answer.body)
    assert_headers(answer)
    assert answer.header("Content-Type") == "application/json; charset=utf-8"
    envelope = answer.json()
    assert envelope["view"] == "error"
    assert envelope["data"] is None
    assert [notice["kind"] for notice in envelope["notices"]] == [kind]
    assert isinstance(envelope["notices"][0]["text"], str) and envelope["notices"][0]["text"]
    return envelope


# -- routes ------------------------------------------------------------------------------


ROUTED = [
    ("/api/about", "about", ()),
    ("/api/runs", "runs", ()),
    ("/api/run?ref=20261027T000000Z-abcd1234", "run", ("20261027T000000Z-abcd1234",)),
    ("/api/run?ref=fleet%2F001-entry%2Frun", "run", ("fleet/001-entry/run",)),
    ("/api/run/messages?ref=r", "messages", ("r", 0, 100)),
    ("/api/run/messages?ref=r&offset=40&limit=20", "messages", ("r", 40, 20)),
    ("/api/run/messages?limit=500&ref=r&offset=0", "messages", ("r", 0, 500)),
    ("/api/run/messages?ref=r&limit=0", "messages", ("r", 0, 0)),
    ("/api/run/message?ref=r&seq=7", "message", ("r", 7)),
    ("/api/store/runs", "store_runs", ()),
    ("/api/store/findings?provenance=reference", "store_findings", ("reference",)),
    ("/api/store/findings?provenance=poison", "store_findings", ("poison",)),
    ("/api/store/candidates", "store_candidates", ()),
    ("/api/store/diff?before=abcdef12&after=12345678", "store_diff", ("abcdef12", "12345678")),
    ("/api/fleets", "fleets", ()),
    ("/api/fleet?id=f-1", "fleet", ("f-1",)),
    ("/api/fleets/compare", "fleet_compare", (None, None)),
    ("/api/fleets/compare?before=a&after=b", "fleet_compare", ("a", "b")),
    ("/api/fleets/compare?before=a", "fleet_compare", ("a", None)),
    ("/api/corpus", "corpora", ()),
    ("/api/corpus?i=2", "corpus", (2,)),
    ("/api/scenarios", "scenarios", ()),
    ("/api/scenario?i=0", "scenario", (0,)),
    ("/api/signals", "signals", ()),
    ("/api/run?ref=", "run", ("",)),
    ("/api/run?ref=a+b%20c", "run", ("a b c",)),
    ("/api/store/engagement", "store_engagement", ()),
    ("/api/store/triage", "triage", ()),
    ("/api/store/triage/history?finding=4", "triage_history", (4,)),
    ("/api/store/triage/review?finding=12", "triage_review", (12,)),
    ("/api/bundles", "bundles", ()),
    ("/api/bundle?i=1", "bundle", (1,)),
    ("/api/attestations", "attestations", ()),
    ("/api/attestation?i=0", "attestation", (0,)),
]

DOWNLOADED = [
    (
        "/api/bundle/file?i=0&path=runs%2Fa%2Fevents.jsonl",
        "bundle_file",
        (0, "runs/a/events.jsonl"),
    ),
    ("/api/bundle/file?path=report.md&i=2", "bundle_file", (2, "report.md")),
    ("/api/attestation/file?i=1", "attestation_file", (1,)),
]


@pytest.mark.parametrize(("target", "function", "arguments"), ROUTED)
def test_every_route_calls_its_view_with_its_parameters(
    server, stand_in, target, function, arguments
):
    answer = ask(server, target)
    assert answer.status == 200, answer.body
    assert_headers(answer)
    assert answer.header("Content-Type") == "application/json; charset=utf-8"
    assert stand_in.calls == [(function, arguments)]
    assert answer.json() == {
        "view": function,
        "notices": [],
        "data": {"arguments": list(arguments)},
    }


@pytest.mark.parametrize(("target", "function", "arguments"), DOWNLOADED)
def test_a_download_is_an_attachment_of_bytes_with_the_headers(
    server, stand_in, target, function, arguments
):
    answer = ask(server, target)
    assert answer.status == 200, answer.body
    assert_headers(answer)
    assert answer.header("Content-Type") == "application/octet-stream"
    assert answer.header("Content-Disposition") == (
        f"attachment; filename=\"{function}.bin\"; filename*=UTF-8''{function}.bin"
    )
    assert stand_in.calls == [(function, arguments)]
    assert json.loads(answer.body) == list(arguments)
    head = ask(server, target, method="HEAD")
    assert (head.status, head.body) == (200, b"")
    assert head.header("Content-Length") == str(len(answer.body))
    assert head.header("Content-Disposition") == answer.header("Content-Disposition")


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_a_download_answers_get_and_head_only(server, stand_in, method):
    answer = ask(server, "/api/attestation/file?i=0", method=method)
    assert_error(answer, 405, "method_not_allowed")
    assert stand_in.calls == []


@pytest.mark.parametrize(
    ("name", "plain"),
    [
        ("report.md", "report.md"),
        ('a"b\r\nSet-Cookie: x.md', "a_b__Set-Cookie__x.md"),
        ("ünïcode‮.md", "_n_code_.md"),
        ("..", "download"),
        ("", "download"),
    ],
)
def test_a_download_s_name_cannot_end_its_header_or_add_one(server, stand_in, name, plain):
    stand_in.behaviour["attestation_file"] = lambda: Download(name, b"x")
    answer = ask(server, "/api/attestation/file?i=0")
    assert answer.status == 200
    disposition = answer.header("Content-Disposition")
    assert disposition.startswith(f"attachment; filename=\"{plain}\"; filename*=UTF-8''")
    assert disposition.isascii() and "\r" not in disposition and "\n" not in disposition
    assert answer.header("Set-Cookie") is None


def test_a_download_view_that_refuses_is_its_status_in_the_error_envelope(server, stand_in):
    stand_in.behaviour["bundle_file"] = ViewError(409, "the bundle is not intact")
    envelope = assert_error(ask(server, "/api/bundle/file?i=0&path=x"), 409, "conflict")
    assert envelope["notices"][0]["text"] == "the bundle is not intact"
    stand_in.behaviour["bundle_file"] = ViewError(404, "not listed")
    assert_error(ask(server, "/api/bundle/file?i=0&path=x"), 404, "not_found")


def test_a_download_view_that_gives_no_download_is_a_500(server, stand_in, capsys):
    stand_in.behaviour["bundle_file"] = lambda: {"view": "x", "notices": [], "data": None}
    assert_error(ask(server, "/api/bundle/file?i=0&path=x"), 500, "internal_error")
    assert "not a Download" in capsys.readouterr().err


def test_the_route_table_is_the_contract_s_and_every_function_exists_in_views():
    from mcp_kymograph.web import views

    called = {route.function for route in web.ROUTES.values()} | {"corpus"}
    assert called == set(StandIn.FUNCTIONS)
    for name in called:
        assert callable(getattr(views, name)), name


BAD_QUERIES = [
    "/api/run",  # required, missing
    "/api/run?ref=a&ref=b",  # twice
    "/api/run?ref=a&extra=1",  # not a parameter of this view
    "/api/runs?x=1",
    "/api/about?",  # an empty query is no parameter, but '?' alone parses as none: see below
    "/api/run?ref=a&&",  # malformed under strict parsing
    "/api/run?ref",  # no '='
    "/api/run?ref=%ff",  # not UTF-8
    "/api/run/message?ref=r",  # seq missing
    "/api/run/message?ref=r&seq=",  # empty integer
    "/api/run/message?ref=r&seq=-1",
    "/api/run/message?ref=r&seq=%2B1",
    "/api/run/message?ref=r&seq=1.0",
    "/api/run/message?ref=r&seq=1e3",
    "/api/run/message?ref=r&seq=%201",
    "/api/run/message?ref=r&seq=1_000",
    "/api/run/message?ref=r&seq=%D9%A3",  # an Arabic-Indic digit: int() takes it, we do not
    "/api/run/message?ref=r&seq=1234567890123456789",  # longer than any index
    "/api/run/messages?ref=r&limit=501",
    "/api/run/messages?ref=r&offset=x",
    "/api/run/messages?ref=r&offset=1&offset=2",
    "/api/store/findings",
    "/api/store/findings?provenance=real-world",
    "/api/store/findings?provenance=Reference",
    "/api/store/diff?before=a",
    "/api/fleet",
    "/api/fleets/compare?before=a&before=b",
    "/api/corpus?i=x",
    "/api/corpus?i=1&i=2",
    "/api/corpus?i=1&x=2",
    "/api/corpus?x=1",
    "/api/scenario",
    "/api/scenario?i=-3",
    "/api/store/triage/review",
    "/api/store/triage/review?finding=x",
    "/api/store/triage/review?finding=1&finding=2",
    "/api/store/triage/history?finding=-1",
    "/api/store/triage?finding=1",
    "/api/bundle",
    "/api/bundle/file?i=0",
    "/api/bundle/file?path=x",
    "/api/bundle/file?i=0&path=a&path=b",
    "/api/attestation/file",
    "/api/attestation/file?i=0&path=x",
    "/api/run?" + "&".join(f"f{n}=1" for n in range(20)),  # more fields than any view takes
]


@pytest.mark.parametrize("target", [t for t in BAD_QUERIES if t != "/api/about?"])
def test_a_parameter_missing_twice_unknown_or_malformed_is_a_400_and_calls_no_view(
    server, stand_in, target
):
    answer = ask(server, target)
    assert_error(answer, 400, "bad_request")
    assert stand_in.calls == []


def test_a_question_mark_with_nothing_after_it_is_no_parameter(server, stand_in):
    assert ask(server, "/api/about?").status == 200
    assert stand_in.calls == [("about", ())]


def test_real_world_findings_are_refused_with_where_they_are(server):
    text = ask(server, "/api/store/findings?provenance=real-world").json()["notices"][0]["text"]
    assert "/api/store/candidates" in text


@pytest.mark.parametrize(("status", "kind"), [(404, "not_found"), (400, "bad_request")])
def test_a_view_error_is_its_status_and_its_words_in_the_error_envelope(
    server, stand_in, status, kind
):
    stand_in.behaviour["run"] = ViewError(status, "no run 'x' under --runs")
    envelope = assert_error(ask(server, "/api/run?ref=x"), status, kind)
    assert envelope["notices"][0]["text"] == "no run 'x' under --runs"


def test_a_view_error_of_another_status_is_a_500(server, stand_in, capsys):
    stand_in.behaviour["about"] = ViewError(418, "teapot")
    assert_error(ask(server, "/api/about"), 500, "internal_error")
    assert "418" in capsys.readouterr().err


def test_a_failing_view_is_a_500_whose_details_are_on_stderr_only(server, stand_in, capsys):
    stand_in.behaviour["runs"] = RuntimeError(TRACE_MARK + "‮\x1b[31m")
    answer = ask(server, "/api/runs")
    assert_error(answer, 500, "internal_error")
    assert TRACE_MARK.encode() not in answer.body
    assert b"Traceback" not in answer.body and b"RuntimeError" not in answer.body
    err = capsys.readouterr().err
    assert TRACE_MARK in err and "Traceback" in err
    assert "‮" not in err and "\x1b" not in err, "made safe for a terminal first"


@pytest.mark.parametrize(
    "envelope",
    [
        lambda: {"view": "x", "notices": [], "data": float("nan")},
        lambda: {"view": "x", "notices": [], "data": object()},
    ],
)
def test_an_envelope_that_is_not_json_is_a_500(server, stand_in, envelope, capsys):
    stand_in.behaviour["about"] = envelope
    assert_error(ask(server, "/api/about"), 500, "internal_error")
    capsys.readouterr()


def test_json_is_ascii_whatever_the_view_carries(server, stand_in):
    hostile = "‮<script>alert(1)</script>​\U0001f600"
    stand_in.behaviour["about"] = lambda: {"view": "about", "notices": [], "data": hostile}
    answer = ask(server, "/api/about")
    assert answer.status == 200
    answer.body.decode("ascii")  # nothing but ASCII on the wire
    assert b"\\u202e" in answer.body
    assert answer.json()["data"] == hostile


# -- who may ask -------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "FOO"])
def test_only_get_and_head_are_answered(server, stand_in, method):
    answer = ask(server, "/api/about", method=method, extra=[("Content-Length", "0")])
    assert_error(answer, 405, "method_not_allowed")
    assert answer.header("Allow") == "GET, HEAD"
    assert stand_in.calls == []


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "evil.example:{port}",
        "127.0.0.1",
        "localhost",
        "localhost:1",
        "127.0.0.1:{other}",
        "127.0.0.2:{port}",
        "localhost.:{port}",
        "attacker.localhost:{port}",
        "0.0.0.0:{port}",
        "[::ffff:127.0.0.1]:{port}",
        "[::1]:{port}",
        "",
    ],
)
def test_a_host_that_is_not_this_server_s_is_a_421(server, stand_in, host):
    host = host.format(port=server.port, other=server.port + 1)
    assert_error(ask(server, "/api/about", host=host), 421, "misdirected_request")
    assert_error(ask(server, "/", host=host), 421, "misdirected_request")
    assert stand_in.calls == []


def test_a_request_without_host_or_with_two_is_a_421(server, stand_in):
    assert_error(ask(server, "/api/about", host=None), 421, "misdirected_request")
    two = parse_raw(
        ask_raw(
            server,
            f"GET /api/about HTTP/1.1\r\nHost: {own_host(server)}\r\nHost: evil.example\r\n\r\n"
            .encode(),
        )
    )  # fmt: skip
    assert_error(two, 421, "misdirected_request")
    bare = parse_raw(ask_raw(server, b"GET /api/about HTTP/1.0\r\n\r\n"))
    assert_error(bare, 421, "misdirected_request")
    assert stand_in.calls == []


@pytest.mark.parametrize("host", ["127.0.0.1:{port}", "localhost:{port}", "LOCALHOST:{port}"])
def test_the_hosts_that_name_this_server_are_answered(server, host):
    assert ask(server, "/api/about", host=host.format(port=server.port)).status == 200


@pytest.mark.parametrize(
    "origin",
    [
        "http://evil.example",
        "null",
        "http://localhost:{port}",  # another origin than the Host the request came by
        "https://127.0.0.1:{port}",
        "http://127.0.0.1:{other}",
        "http://127.0.0.1",
        "http://127.0.0.1:{port}/",
        "",
    ],
)
def test_an_origin_that_is_not_the_page_s_own_is_a_403(server, stand_in, origin):
    origin = origin.format(port=server.port, other=server.port + 1)
    assert_error(ask(server, "/api/about", origin=origin), 403, "forbidden")
    assert_error(ask(server, "/static/app.js", origin=origin), 403, "forbidden")
    assert stand_in.calls == []


def test_the_page_s_own_origin_and_none_are_answered(server):
    assert ask(server, "/api/about", origin=f"http://{own_host(server)}").status == 200
    localhost = f"localhost:{server.port}"
    assert ask(server, "/api/about", host=localhost, origin=f"http://{localhost}").status == 200
    assert ask(server, "/api/about").status == 200


def test_two_origins_are_a_403(server):
    own = f"http://{own_host(server)}"
    answer = ask(server, "/api/about", origin=own, extra=[("Origin", own)])
    assert_error(answer, 403, "forbidden")


def test_the_host_is_refused_before_the_method_and_the_method_before_the_origin(server):
    assert ask(server, "/", method="POST", host="evil.example").status == 421
    assert ask(server, "/", method="POST", origin="http://evil.example").status == 405
    assert ask(server, "/", origin="http://evil.example").status == 403


# -- headers, HEAD, the request line -----------------------------------------------------


def test_every_answer_carries_the_headers_errors_included(server, stand_in, capsys):
    stand_in.behaviour["signals"] = RuntimeError("boom")
    answers = [
        ask(server, "/api/about"),
        ask(server, "/"),
        ask(server, "/static/app.css"),
        ask(server, "/nothing"),
        ask(server, "/api/run"),
        ask(server, "/api/signals"),
        ask(server, "/", method="DELETE"),
        ask(server, "/", host="evil.example"),
        ask(server, "/", origin="http://evil.example"),
        ask(server, "/api/about", method="HEAD"),
        parse_raw(ask_raw(server, b"GARBAGE\r\n\r\n")),
        parse_raw(ask_raw(server, b"GET / HTTP/9.9\r\n\r\n")),
        parse_raw(ask_raw(server, b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n")),
    ]
    for answer in answers:
        assert_headers(answer)
        assert answer.header("Content-Length") is not None
    assert [answer.status for answer in answers] == [
        200, 200, 200, 404, 400, 500, 405, 421, 403, 200, 400, 505, 414
    ]  # fmt: skip
    capsys.readouterr()


def test_head_has_the_get_s_headers_and_no_body(server):
    for target in ("/api/about", "/", "/static/app.js", "/nothing"):
        got = ask(server, target)
        head = ask(server, target, method="HEAD")
        assert head.status == got.status
        assert head.body == b""
        assert head.header("Content-Length") == str(len(got.body))
        assert head.header("Content-Type") == got.header("Content-Type")
        assert_headers(head)


def test_an_absolute_form_request_target_is_a_400(server, stand_in):
    raw = (
        f"GET http://{own_host(server)}/api/about HTTP/1.1\r\nHost: {own_host(server)}\r\n"
        f"Cookie: {session_cookie(server)}\r\n\r\n"
    )
    assert_error(parse_raw(ask_raw(server, raw.encode())), 400, "bad_request")
    assert stand_in.calls == []


def test_an_http_0_9_request_gets_no_answer_at_all(server, stand_in):
    """An HTTP/0.9 answer has no headers, so it could not carry the security headers."""
    assert ask_raw(server, b"GET /api/about\r\n") == b""
    assert stand_in.calls == []


def test_the_server_keeps_no_request_log_and_says_nothing_while_serving(server, capfd):
    capfd.readouterr()
    for target in ("/", "/api/about", "/nothing", "/static/../secret.txt", "/api/run"):
        ask(server, target)
    ask(server, "/", host="evil.example")
    ask(server, "/", method="POST")
    ask_raw(server, b"GARBAGE\r\n\r\n")
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_a_silent_client_does_not_hold_a_thread_forever():
    assert 0 < web._Handler.timeout <= 60
    assert web.Server.daemon_threads


# -- static files ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("target", "content_type", "body"),
    [
        ("/", "text/html; charset=utf-8", b"<!doctype html><title>index</title>"),
        ("/static/index.html", "text/html; charset=utf-8", b"<!doctype html><title>index</title>"),
        ("/static/app.css", "text/css; charset=utf-8", b"body { color: black; }"),
        ("/static/app.js", "text/javascript; charset=utf-8", b"'use strict';"),
        ("/static/mark.svg", "image/svg+xml", b"<svg></svg>"),
        ("/static/font.woff2", "font/woff2", b"wOF2\x00"),
        ("/static/image.png", "image/png", b"\x89PNG\r\n"),
        ("/static/app.css?v=1", "text/css; charset=utf-8", b"body { color: black; }"),
        ("/?x", "text/html; charset=utf-8", b"<!doctype html><title>index</title>"),
        ("/index.html", "text/html; charset=utf-8", b"<!doctype html><title>index</title>"),
        ("/app.css", "text/css; charset=utf-8", b"body { color: black; }"),
        ("/app.js", "text/javascript; charset=utf-8", b"'use strict';"),
        ("/image.png", "image/png", b"\x89PNG\r\n"),
    ],
)
def test_the_static_files_are_served_by_exact_name_with_their_type(
    server, target, content_type, body
):
    answer = ask(server, target)
    assert answer.status == 200
    assert answer.header("Content-Type") == content_type
    assert answer.body == body
    assert_headers(answer)


def test_the_listing_is_the_allowlist(static_dir):
    assert sorted(web.static_files(static_dir)) == [
        "app.css", "app.js", "font.woff2", "image.png", "index.html", "mark.svg"
    ]  # fmt: skip


TRAVERSALS = [
    "/static/../secret.txt",
    "/static/../secret.css",
    "/static/%2e%2e/secret.css",
    "/static/%2E%2E%2Fsecret.css",
    "/static/..%2fsecret.css",
    "/static/..%2Fsecret.css",
    "/static/%252e%252e%252fsecret.css",
    "/static/..\\secret.css",
    "/static/%5c..%5csecret.css",
    "/static/..%5csecret.css",
    "/static/app.css%00",
    "/static/app.css%00.png",
    "/static/./app.css",
    "/static//app.css",
    "/static/app.css/",
    "/static/app.css/.",
    "/static/APP.CSS",
    "/static/%61pp.css",
    "/static/sub/inner.css",
    "/static/sub/",
    "/static/sub",
    "/static/",
    "/static",
    "/static/.hidden.css",
    "/static/notes.txt",
    "/static/notes.json",
    "/static/with%20space.css",
    "/static/link.css",
    "/../secret.txt",
    "/secret.txt",
    "/notes.txt",
    "/.hidden.css",
    "/link.css",
    "/sub/inner.css",
    "/with%20space.css",
    "/app.css/",
    "/%2e%2e/secret.css",
    "/..%2fsecret.css",
    "/static/%2fetc%2fpasswd",
    "/static//etc/passwd",
    "/static/~",
    "/api",
    "/api/",
    "/api/runs/",
    "/api/../api/runs",
    "/api/r%75ns",
    "/API/RUNS",
]


@pytest.mark.parametrize("target", TRAVERSALS)
def test_nothing_outside_the_allowlist_is_served_however_it_is_written(server, stand_in, target):
    answer = ask(server, target)
    assert_error(answer, 404, "not_found")
    assert OUTSIDE.encode() not in answer.body
    assert stand_in.calls == []


@pytest.mark.parametrize(
    "raw_target",
    [b"/static/app.css\x00", b"/static/..\\..\\secret.css", b"/static/\xff", b"/static/a\tb"],
)
def test_raw_bytes_in_the_path_are_not_served(server, raw_target):
    head = f"HTTP/1.1\r\nHost: {own_host(server)}\r\nCookie: {session_cookie(server)}\r\n\r\n"
    raw = b"GET " + raw_target + b" " + head.encode()
    answer = parse_raw(ask_raw(server, raw))
    assert answer.status in (400, 404)
    assert OUTSIDE.encode() not in answer.body
    assert_headers(answer)


def test_without_an_index_the_root_is_a_404(tmp_path, stand_in):
    empty = tmp_path / "nothing-here"
    for static in (empty, tmp_path / "missing"):
        if static == empty:
            empty.mkdir()
        running, thread = serve(stand_in, static)
        try:
            assert_error(ask(running, "/"), 404, "not_found")
            assert ask(running, "/api/about").status == 200
        finally:
            running.shutdown()
            running.server_close()
            thread.join(timeout=10)


def test_a_file_added_after_the_start_is_not_served(server, static_dir):
    (static_dir / "late.css").write_text("late")
    assert ask(server, "/static/late.css").status == 404


# -- the address -------------------------------------------------------------------------


def test_127_0_0_1_is_taken():
    assert str(web.loopback("127.0.0.1")) == "127.0.0.1"


def test_the_bind_literals_are_127_0_0_1_alone_and_narrower_than_the_tool_s_loopback_set():
    # authorization's sets are used elsewhere and stay as they are; the interface has its own.
    assert {"127.0.0.1"} == web.BIND_LITERALS
    assert web.BIND_LITERALS < LOOPBACK_LITERALS


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # noqa: S104 - refused, which is the point
        "::",
        "::1",
        "localhost",
        "192.168.1.10",
        "10.0.0.1",
        "169.254.1.1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::1%lo",
        "0:0:0:0:0:0:0:2",
        # the rest of 127.0.0.0/8
        "127.0.0.2",
        "127.255.255.254",
        # other spellings of ::1 and of 127.0.0.1: nothing is normalised
        "0:0::1",
        "0000::1",
        "0:0:0:0:0:0:0:1",
        "127.1",
        "127.0.0.1.",
        "example.org",
        "127.0.0.1:8765",
        "[::1]",
        "",
        " 127.0.0.1",
    ],
)
def test_anything_but_127_0_0_1_is_refused(address, stand_in, tmp_path):
    with pytest.raises(ValueError, match="^must be 127.0.0.1, not "):
        web.loopback(address)
    with pytest.raises(ValueError, match="^must be 127.0.0.1, not "):
        web.make_server(Sources(), address, 0, views=stand_in, static=tmp_path)


def test_a_port_in_use_is_an_os_error(server, stand_in, static_dir):
    with pytest.raises(OSError):
        web.make_server(Sources(), "127.0.0.1", server.port, views=stand_in, static=static_dir)


def test_the_host_names_are_127_0_0_1_and_localhost_with_the_bound_port(server):
    assert {"127.0.0.1", "localhost"} == web.HOST_NAMES
    assert server.hosts == {f"127.0.0.1:{server.port}", f"localhost:{server.port}"}
    # authorization.LOCAL_TARGETS is wider (it has ::1) and is not touched
    assert (LOCAL_TARGETS | {"127.0.0.1"}) > web.HOST_NAMES


def test_the_url_names_the_bound_address_and_port(server):
    assert server.url == f"http://127.0.0.1:{server.port}/"
    assert server.start_url == f"http://127.0.0.1:{server.port}/?token={server.token}"
    assert server.port != 0


# -- the start token and the session -----------------------------------------------------

REFUSED_WORDS = "refused: open the address printed when the interface started"
SET_COOKIE = "{name}={session}; Path=/; HttpOnly; SameSite=Strict"


def assert_session_refused(answer: Answer) -> None:
    envelope = assert_error(answer, 403, "forbidden")
    assert envelope["notices"][0]["text"] == REFUSED_WORDS
    assert answer.header("Set-Cookie") is None


def test_the_token_and_the_session_are_drawn_at_start_and_differ(server, stand_in, static_dir):
    other, thread = serve(stand_in, static_dir)
    try:
        values = {server.token, server.session, other.token, other.session}
        assert len(values) == 4
        for value in values:
            assert re.fullmatch(r"[A-Za-z0-9_-]{43}", value)  # token_urlsafe(32)
    finally:
        other.shutdown()
        other.server_close()
        thread.join(timeout=10)


def test_the_cookie_is_named_for_the_bound_port(server):
    assert server.port != 0
    assert server.cookie_name == f"kymograph-{server.port}"


TARGETS = [
    "/",
    "/index.html",
    "/static/app.css",
    "/app.js",
    "/api/about",
    "/api/runs",
    "/api/bundle/file?i=0&path=report.md",
    "/api/attestation/file?i=0",
    "/nothing",
]


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("target", TARGETS)
def test_every_route_without_the_cookie_is_a_403(server, stand_in, target, method):
    answer = ask(server, target, method=method, cookie=None)
    assert answer.status == 403
    assert_headers(answer)
    if method == "GET":
        assert_session_refused(answer)
    assert stand_in.calls == [], "refused before any route is looked up"


def test_a_refusal_is_the_same_for_a_route_that_exists_and_one_that_does_not(server):
    bodies = {ask(server, target, cookie=None).body for target in TARGETS}
    assert len(bodies) == 1


def test_a_wrong_token_is_a_403_and_no_exchange(server, stand_in):
    token = server.token
    for query in (
        "token=wrong",
        "token=",
        "token",
        f"token={token}x",
        f"token={token[:-1]}",
        f"token={token.swapcase()}",
        f"token={token}&x=1",
        f"x=1&token={token}",
        f"token={token}&token={token}",
        f"TOKEN={token}",
        f"token={token}#",
        f"token=%{ord(token[0]):02x}{token[1:]}",
    ):
        answer = ask(server, f"/?{query}", cookie=None)
        assert_session_refused(answer)
    assert stand_in.calls == []


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_the_right_token_at_the_root_is_exchanged_for_the_cookie(server, method):
    answer = ask(server, f"/?token={server.token}", method=method, cookie=None)
    assert answer.status == 303
    assert answer.header("Location") == "/"
    expected = SET_COOKIE.format(name=f"kymograph-{server.port}", session=server.session)
    assert answer.header("Set-Cookie") == expected
    assert [n for n, _ in answer.header_list if n.lower() == "set-cookie"] == ["Set-Cookie"]
    assert answer.body == b""
    assert_headers(answer)


def test_the_exchange_may_be_repeated_and_sets_the_same_session(server):
    cookies = {
        ask(server, f"/?token={server.token}", cookie=None).header("Set-Cookie") for _ in range(3)
    }
    assert len(cookies) == 1
    # a browser that already holds the cookie may exchange again
    again = ask(server, f"/?token={server.token}")
    assert again.status == 303
    assert again.header("Set-Cookie") in cookies


def test_the_cookie_the_exchange_sets_opens_the_interface(server):
    given = ask(server, f"/?token={server.token}", cookie=None).header("Set-Cookie")
    cookie = given.split(";")[0]
    assert cookie == session_cookie(server)
    answer = ask(server, "/", cookie=cookie)
    assert answer.status == 200
    assert answer.body == b"<!doctype html><title>index</title>"


def test_the_exchange_is_checked_for_host_method_and_origin_first(server):
    start = f"/?token={server.token}"
    assert ask(server, start, host="evil.example", cookie=None).status == 421
    assert ask(server, start, method="POST", cookie=None).status == 405
    refused = ask(server, start, origin="http://evil.example", cookie=None)
    assert refused.status == 403
    assert refused.header("Set-Cookie") is None


@pytest.mark.parametrize(
    "target",
    [
        "/index.html",
        "/static/app.css",
        "/api/about",
        "/api/runs",
        "/api/about?x=1",
        "/nothing",
    ],
)
def test_the_right_token_at_another_address_is_not_exchanged(server, stand_in, target):
    joiner = "&" if "?" in target else "?"
    target = f"{target}{joiner}token={server.token}"
    without = ask(server, target, cookie=None)
    assert_session_refused(without)
    assert stand_in.calls == []
    # with the cookie, an unknown parameter of a view or of a file
    with_cookie = ask(server, target)
    assert with_cookie.header("Set-Cookie") is None
    assert_error(with_cookie, 400, "bad_request")
    assert "unknown parameter" in with_cookie.json()["notices"][0]["text"]
    assert stand_in.calls == []


def test_the_right_token_with_another_parameter_at_the_root_is_not_exchanged(server):
    target = f"/?token={server.token}&x=1"
    assert_session_refused(ask(server, target, cookie=None))
    assert ask(server, target).status == 400


@pytest.mark.parametrize(
    "cookie",
    [
        "{name}=wrong",
        "{name}=",
        "{name}={session}x",
        "{name}={token}",
        "{name}={swapped}",
        "kymograph-1={session}",
        "kymograph={session}",
        "{name}x={session}",
        "x{name}={session}",
        "{session}",
        "",
        ";;;",
        "=",
        "====",
        '{name}="{session}"',
        "{name}={session}\x7f",
        "{name}=\xff\xfe",
        "\xff\xfe=\xff\xfe",
        "{name}={session}; {name}={session}",
        "{name}={session}; {name}=wrong",
        "{name}=wrong; {name}={session}",
    ],
)
def test_a_cookie_that_is_not_exactly_the_session_is_a_403(server, stand_in, cookie):
    cookie = cookie.format(
        name=server.cookie_name,
        session=server.session,
        token=server.token,
        swapped=server.session.swapcase(),
    )
    for target in ("/", "/api/about"):
        answer = ask(server, target, cookie=cookie)
        assert_session_refused(answer)
    assert stand_in.calls == []


def test_other_cookies_do_not_matter_and_two_of_the_own_name_are_a_403(server, stand_in):
    own = session_cookie(server)
    for cookie in (
        f"theme=dark; {own}",
        f"{own}; theme=dark",
        f"a=1;{own};b=2",
        f"kymograph-{server.port + 1}=other; {own}",
        f"junk; ; =x; {own}; =; %%%",
    ):
        assert ask(server, "/api/about", cookie=cookie).status == 200, cookie
    assert ask(server, "/api/about", cookie=f"{own}; {own}").status == 403
    # the same cookie in two headers is two cookies as well; so is a good one beside a bad one
    assert ask(server, "/api/about", cookie=own, extra=[("Cookie", own)]).status == 403
    both = ask(server, "/api/about", cookie=own, extra=[("Cookie", f"{server.cookie_name}=x")])
    assert both.status == 403
    # a cookie in a second header is read as well
    second = ask(server, "/api/about", cookie="theme=dark", extra=[("Cookie", own)])
    assert second.status == 200
    assert len(stand_in.calls) == 6


def test_a_broken_cookie_header_is_a_403_and_not_a_500(server):
    for raw in (
        b"Cookie: " + b"a=b;" * 5000,
        b"Cookie: \xff\xfe\x80",
        b"Cookie: =;=;=",
        b"Cookie:",
        b"Cookie: " + server.cookie_name.encode() + b"=\xff",
    ):
        request = (
            f"GET /api/about HTTP/1.1\r\nHost: {own_host(server)}\r\n".encode() + raw + b"\r\n\r\n"
        )
        answer = parse_raw(ask_raw(server, request))
        assert answer.status in (403, 431), (raw[:20], answer.status)
        assert_headers(answer)


def test_the_session_is_checked_after_the_host_the_method_and_the_origin(server):

    def words(answer):
        return answer.json()["notices"][0]["text"]

    assert ask(server, "/", host="evil.example", cookie=None).status == 421
    assert ask(server, "/", method="POST", cookie=None).status == 405
    foreign = ask(server, "/", origin="http://evil.example", cookie=None)
    assert foreign.status == 403
    assert words(foreign) != REFUSED_WORDS, "the Origin's words, not the session's"
    assert words(ask(server, "/", cookie=None)) == REFUSED_WORDS
    # a good cookie does not make up for a foreign Origin
    assert ask(server, "/", origin="http://evil.example").status == 403


def test_two_servers_at_once_have_two_cookie_names_and_do_not_open_each_other(
    server, stand_in, static_dir
):
    other, thread = serve(stand_in, static_dir)
    try:
        assert other.cookie_name != server.cookie_name
        assert other.cookie_name == f"kymograph-{other.port}"
        assert ask(other, "/api/about").status == 200
        # the cookie of one under the name of the other, and the token of one at the other
        assert ask(other, "/api/about", cookie=session_cookie(server)).status == 403
        assert (
            ask(other, "/api/about", cookie=f"{other.cookie_name}={server.session}").status == 403
        )
        assert ask(other, f"/?token={server.token}", cookie=None).status == 403
        # a browser holding both cookies sends both, and each server reads its own
        both = f"{session_cookie(server)}; {session_cookie(other)}"
        assert ask(server, "/api/about", cookie=both).status == 200
        assert ask(other, "/api/about", cookie=both).status == 200
    finally:
        other.shutdown()
        other.server_close()
        thread.join(timeout=10)


def test_the_token_and_the_session_are_in_no_answer_and_not_on_stderr(server, stand_in, capfd):
    """Every refusal, a 500 and the rest, with the token in the request in every way it could
    be echoed. Only the one Set-Cookie of the exchange holds the session; the token is in no
    answer at all."""
    stand_in.behaviour["signals"] = RuntimeError("boom")
    stand_in.behaviour["runs"] = ViewError(418, "not a status a view may refuse with")
    token, session = server.token, server.session
    capfd.readouterr()
    answers = [
        ask(server, "/api/signals"),  # a 500
        ask(server, "/api/runs"),  # a 500 as well, by a status that is not a view's
        ask(server, "/api/signals", method="HEAD"),
        ask(server, f"/api/signals?token={token}"),
        ask(server, f"/{token}"),
        ask(server, f"/static/{token}.css"),
        ask(server, f"/?token={token}&x=1"),
        ask(server, f"/?token={token}x", cookie=None),
        ask(server, f"/api/about?token={token}", cookie=None),
        ask(server, "/", cookie=None),
        ask(server, "/", cookie=f"{server.cookie_name}={token}"),
        ask(server, "/", cookie=f"{server.cookie_name}={session}x"),
        ask(server, "/", host=f"{token}.example", cookie=None),
        ask(server, f"/?token={token}", host="evil.example", cookie=None),
        ask(server, f"/?token={token}", method="POST", cookie=None),
        ask(server, f"/?token={token}", origin=f"http://{token}.example", cookie=None),
        ask(server, "/api/about", extra=[("X-Token", token)], origin=f"http://{token}"),
        parse_raw(ask_raw(server, f"GET /{token} HTTP/9.9\r\n\r\n".encode())),
        parse_raw(ask_raw(server, f"{token}\r\n\r\n".encode())),
        parse_raw(ask_raw(server, f"GET /?{'a' * 70000}{token} HTTP/1.1\r\n\r\n".encode())),
        parse_raw(ask_raw(server, f"GET http://{token}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())),
    ]
    assert [a.status for a in answers[:3]] == [500, 500, 500]
    exchange = ask(server, f"/?token={token}", cookie=None)
    for answer in [*answers, exchange]:
        wire = answer.body + repr(answer.header_list).encode()
        assert token.encode() not in wire
        if answer is not exchange:
            assert session.encode() not in wire
    assert exchange.header("Set-Cookie").startswith(f"{server.cookie_name}={session};")
    assert session.encode() not in exchange.body
    others = [(n, v) for n, v in exchange.header_list if n.lower() != "set-cookie"]
    assert session not in repr(others)
    captured = capfd.readouterr()
    assert captured.out == ""
    assert "boom" in captured.err, "the 500 did report, to stderr"
    assert token not in captured.err
    assert session not in captured.err


def test_no_error_path_of_the_handler_writes_the_request_to_the_log(server, capfd):
    token = server.token
    capfd.readouterr()
    handler = web._Handler
    assert handler.log_message(None, "%s", token) is None
    ask_raw(server, f"GET /{token} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", "")


# -- the page refers to nothing outside itself -------------------------------------------

#: A scheme that leaves the page, anywhere in a file, followed by anything a URL could go on
#: with (``http:x`` is a URL to ``http://x/`` for a browser). Not a scheme: ``http: 'HTTP'``, a
#: key in a script. An XML namespace is a name, not a request.
_SCHEME = re.compile(r"""(?i)\b(?:https?|wss?|ftp):(?=[^\s'"`])""")
_NAMESPACE = re.compile(r"""(?i)xmlns(?::[\w-]+)?\s*=\s*["']https?://www\.w3\.org/[^"']*["']""")
#: A protocol-relative address where the page would load or send something.
_RELATIVE = re.compile(
    r"""(?ix)
    (?: \b(?:src|href|action|formaction|srcset|poster|data|xlink:href)\s*=\s*["']?
      | url\(\s*["']?
      | @import\s+(?:url\(\s*)?["']?
      | \b(?:fetch|EventSource|WebSocket|importScripts|import)\s*\(\s*["'`]
      | \bfrom\s+["']
    )\s*(?://|\\\\)
    """
)


def outside_references(directory) -> list[str]:
    found = []
    if not directory.is_dir():
        return found
    for entry in directory.iterdir():
        if not entry.is_file():
            continue
        text = entry.read_bytes().decode("utf-8", "replace")
        without_namespaces = _NAMESPACE.sub("", text)
        for pattern in (_SCHEME, _RELATIVE):
            for match in pattern.finditer(without_namespaces):
                found.append(f"{entry.name}: {match.group(0)!r}")
    return found


def test_no_file_of_the_page_refers_to_anything_outside_it():
    """Passes with no files at all: it scans whatever web/static/ holds."""
    static = resources.files("mcp_kymograph.web") / "static"
    assert outside_references(static) == []


def test_the_scan_finds_what_it_is_for(tmp_path):
    offenders = {
        "a.html": '<link href="https://fonts.example/css">',
        "b.html": "<img src=//cdn.example/x.png>",
        "c.css": "@import url(//cdn.example/x.css);",
        "d.css": "body { background: url( '//cdn.example/x.png' ) }",
        "e.js": "fetch('//cdn.example/api')",
        "f.js": 'const u = "http://example.org/";',
        "g.css": '@import "//cdn.example/y.css";',
        "h.js": "new WebSocket('wss://example.org')",
        "i.html": "<img src='http:example.org/x.png'>",
    }
    for name, text in offenders.items():
        (tmp_path / name).write_text(text)
    found = outside_references(tmp_path)
    assert {line.split(":", 1)[0] for line in found} == set(offenders)

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "ok.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg"></svg>')
    (clean / "ok.js").write_text("// a comment\nfetch('/api/runs'); // another\nconst a = 1 // 2;")
    (clean / "ok.css").write_text("body { background: url('mark.svg') } /* // */")
    (clean / "ok.html").write_text('<script src="/static/app.js"></script>')
    (clean / "keys.js").write_text("const tabs = { http: 'HTTP', https : 1 };")
    assert outside_references(clean) == []


def test_by_default_the_page_s_files_are_the_package_s(stand_in):
    """Whatever web/static/ holds now: listed by the same rule, and the root is its index."""
    package = resources.files("mcp_kymograph.web") / "static"
    running, thread = serve(stand_in, None)
    try:
        assert set(running.static) == set(web.static_files(package))
        assert all(Path(name).suffix in web.STATIC_TYPES for name in running.static)
        answer = ask(running, "/")
        assert answer.status == (200 if "index.html" in running.static else 404)
        assert_headers(answer)
    finally:
        running.shutdown()
        running.server_close()
        thread.join(timeout=10)


def test_a_listed_file_that_became_a_symbolic_link_is_not_followed(server, static_dir):
    (static_dir / "app.css").unlink()
    (static_dir / "app.css").symlink_to(static_dir.parent / "secret.css")
    answer = ask(server, "/static/app.css")
    assert_error(answer, 404, "not_found")
    assert OUTSIDE.encode() not in answer.body


def _parse_request_as_up_to_3_13(self):
    """parse_request as CPython 3.10-3.13 refuses a malformed request line: with
    ``request_version`` still its default, 'HTTP/0.9', for which the base class writes no status
    line and no header. Forced here, so that path is tested on whatever Python runs the test."""
    self.command = None
    self.request_version = self.default_request_version
    assert self.request_version == "HTTP/0.9"
    self.close_connection = True
    self.requestline = str(self.raw_requestline, "iso-8859-1").rstrip("\r\n")
    self.send_error(HTTPStatus.BAD_REQUEST, "Bad request syntax")
    return False


@pytest.mark.parametrize(
    "raw", [b"GARBAGE\r\n\r\n", b"POST /api/about\r\n", b"GET / HTTP/1.1\r\n\r\n"]
)
def test_a_refusal_made_while_the_version_is_still_0_9_has_a_status_line_and_the_headers(
    server, stand_in, monkeypatch, raw
):
    monkeypatch.setattr(web._Handler, "parse_request", _parse_request_as_up_to_3_13)
    answer = ask_raw(server, raw)
    assert answer.startswith(b"HTTP/1.0 400 "), answer[:80]
    assert_error(parse_raw(answer), 400, "bad_request")
    assert stand_in.calls == []


@pytest.mark.parametrize("raw", [b"GARBAGE\r\n\r\n", b"POST /api/about\r\n", b"PUT /\r\n"])
def test_a_malformed_request_line_is_answered_with_a_status_line_and_the_headers(server, raw):
    """Whatever this Python's parse_request sets the version to before it refuses."""
    answer = ask_raw(server, raw)
    assert answer.startswith(b"HTTP/"), answer[:80]
    assert_error(parse_raw(answer), 400, "bad_request")


def test_a_genuine_http_0_9_get_is_still_closed_unanswered(server, stand_in):
    for raw in (b"GET /\r\n", b"GET /api/about\r\n", b"GET /static/app.css\r\n"):
        assert ask_raw(server, raw) == b""
    assert stand_in.calls == []


# -- downloads through the real views: a bundle made by hand ---------------------------------


def hand_made_bundle(directory: Path) -> Path:
    """A bundle whose index lists a tool file, a report and a scenario one directory down, as
    evidence.read_index reads it; nothing else in it."""
    from mcp_kymograph import evidence

    bundle = directory / "bundle"
    files = {
        "tool.json": ("tool", b'{"tool": "x"}\n'),
        "report.md": ("report", b"# a report\n"),
        "scenarios/s.yaml": ("scenario", b"version: 1\n"),
    }
    entries = []
    for path, (role, data) in files.items():
        target = bundle / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        entries.append(evidence.IndexFile(path, hashlib.sha256(data).hexdigest(), len(data), role))
    index = evidence.Index(
        index_version=evidence.INDEX_VERSION,
        engagement_id_declared="acme-2026-10",
        engagement_digest="ab" * 32,
        created_utc="2026-10-29T12:00:00Z",
        derived_from=None,
        triage=None,
        files=tuple(entries),
        note="made by hand",
    )
    (bundle / "index.json").write_bytes(evidence.index_bytes(index))
    assert evidence.verify(bundle).intact
    return bundle


@pytest.fixture
def bundle_server(tmp_path, static_dir):
    from mcp_kymograph.web import views

    bundle = hand_made_bundle(tmp_path)
    running = web.make_server(
        Sources(bundles=(bundle,)), "127.0.0.1", 0, views=views, static=static_dir
    )
    thread = threading.Thread(target=running.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    yield running, bundle
    running.shutdown()
    running.server_close()
    thread.join(timeout=10)


def test_a_listed_file_of_an_intact_bundle_is_downloaded_as_it_is(bundle_server):
    running, bundle = bundle_server
    answer = ask(running, "/api/bundle/file?i=0&path=scenarios%2Fs.yaml")
    assert answer.status == 200
    assert answer.body == (bundle / "scenarios" / "s.yaml").read_bytes()
    assert answer.header("Content-Disposition").startswith('attachment; filename="s.yaml"')
    assert answer.header("Content-Type") == "application/octet-stream"
    assert_headers(answer)


@pytest.mark.parametrize(
    "path", ["index.json", "..%2Fsecret.txt", "scenarios%2F..%2Ftool.json", "nothing", "%2Fetc"]
)
def test_a_path_the_index_does_not_list_is_a_404(bundle_server, path):
    running, _ = bundle_server
    assert_error(ask(running, f"/api/bundle/file?i=0&path={path}"), 404, "not_found")


def test_a_changed_file_is_not_served_nor_any_other_of_its_bundle(bundle_server):
    running, bundle = bundle_server
    (bundle / "report.md").write_bytes(b"# a report, changed\n")
    for path in ("report.md", "tool.json"):
        answer = ask(running, f"/api/bundle/file?i=0&path={path}")
        envelope = assert_error(answer, 409, "conflict")
        assert "not intact" in envelope["notices"][0]["text"]


def test_a_link_in_place_of_a_directory_is_not_followed(bundle_server, tmp_path):
    running, bundle = bundle_server
    (bundle / "scenarios").rename(tmp_path / "elsewhere")
    (bundle / "scenarios").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    assert_error(ask(running, "/api/bundle/file?i=0&path=scenarios%2Fs.yaml"), 409, "conflict")


def test_a_link_in_place_of_a_listed_file_is_not_followed(bundle_server, tmp_path):
    running, bundle = bundle_server
    (tmp_path / "copy.json").write_bytes((bundle / "tool.json").read_bytes())
    (bundle / "tool.json").unlink()
    (bundle / "tool.json").symlink_to(tmp_path / "copy.json")
    assert_error(ask(running, "/api/bundle/file?i=0&path=tool.json"), 409, "conflict")


def test_a_bundle_download_leaves_the_bundle_as_it_was(bundle_server):
    running, bundle = bundle_server

    def state():
        return {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in bundle.rglob("*") if p.is_file()}

    before = state()
    for path in ("tool.json", "report.md", "scenarios%2Fs.yaml", "index.json"):
        ask(running, f"/api/bundle/file?i=0&path={path}")
        ask(running, f"/api/bundle/file?i=0&path={path}", method="HEAD")
    ask(running, "/api/bundle?i=0")
    assert state() == before
