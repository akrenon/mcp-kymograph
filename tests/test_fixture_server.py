"""The fixture server of the benchmark runner (runner/fixture_server.py).

What it must hold: it serves exactly the files it read at start and nothing it can be talked
into (no directory, no redirect, no decoding to another name); it answers DNS for its own names
and for nothing else, and forwards nothing; every request and every question is in the log, one
by one up to a limit and counted past it.
It runs in-process on 127.0.0.1 with free ports: no Docker, no network.
"""

from __future__ import annotations

import http.client
import importlib.util
import io
import json
import socket
import struct
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "bench_fixture_server",
        ROOT / "benchmarks" / "local-servers" / "runner" / "fixture_server.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


fixture_server = _load()

PAGE = b"<!DOCTYPE html><p>MCPB-CANARY-T-0123abcd</p>\n"
NOTE = b"a note\n"
ADDRESS = "10.1.2.3"


class Running:
    def __init__(self, server, out: io.StringIO) -> None:
        self.server = server
        self.out = out

    def events(self, kind: str | None = None) -> list[dict]:
        lines = [json.loads(line) for line in self.out.getvalue().splitlines()]
        return [e for e in lines if kind is None or e["event"] == kind]

    def request(self, method: str, target: str, **headers: str) -> http.client.HTTPResponse:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.http_port, timeout=5)
        connection.request(method, target, headers=headers)
        response = connection.getresponse()
        response.body = response.read()  # type: ignore[attr-defined]
        connection.close()
        return response

    def ask(self, name: str, qtype: int = 1, *, packet: bytes | None = None) -> bytes | None:
        if packet is None:
            labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p)
            packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            packet += labels + b"\0" + struct.pack("!HH", qtype, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.sendto(packet, ("127.0.0.1", self.server.dns_port))
            try:
                return sock.recvfrom(4096)[0]
            except TimeoutError:
                return None


@pytest.fixture
def running(tmp_path):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "canary.html").write_bytes(PAGE)
    (root / "notes.txt").write_bytes(NOTE)
    (root / "data.bin").write_bytes(b"\x00\x01")
    (root / "sub").mkdir()
    (root / "sub" / "inner.txt").write_bytes(b"inner")
    (tmp_path / "outside.txt").write_bytes(b"outside")
    (root / "link.txt").symlink_to(tmp_path / "outside.txt")
    out = io.StringIO()
    server = fixture_server.FixtureServer(
        str(root),
        {"Fixture.Test.": ADDRESS},
        host="127.0.0.1",
        http_port=0,
        dns_port=0,
        out=out,
    )
    server.start()
    try:
        yield Running(server, out)
    finally:
        server.stop()


def _answer(reply: bytes) -> tuple[int, int, int, bytes]:
    ident, flags, questions, answers, _ns, _extra = struct.unpack("!HHHHHH", reply[:12])
    assert ident == 0x1234 and questions == 1
    return flags & 0xF, flags, answers, reply


# -- HTTP ---------------------------------------------------------------------------------


def test_ready_event_names_ports_names_and_files(running):
    (ready,) = running.events("ready")
    assert ready["http_port"] == running.server.http_port
    assert ready["dns_port"] == running.server.dns_port
    assert ready["names"] == {"fixture.test": ADDRESS}
    assert ready["files"] == ["/canary.html", "/data.bin", "/notes.txt"]


def test_get_and_head_serve_the_files(running):
    page = running.request("GET", "/canary.html")
    assert page.status == 200 and page.body == PAGE
    assert page.getheader("Content-Type") == "text/html; charset=utf-8"
    assert page.getheader("Content-Length") == str(len(PAGE))
    notes = running.request("GET", "/notes.txt")
    assert notes.body == NOTE
    assert notes.getheader("Content-Type") == "text/plain; charset=utf-8"
    assert running.request("GET", "/data.bin").getheader("Content-Type") == (
        "application/octet-stream"
    )
    head = running.request("HEAD", "/canary.html")
    assert head.status == 200 and head.body == b""
    assert head.getheader("Content-Length") == str(len(PAGE))


def _raw(running, method: str, target: str) -> tuple[bytes, bytes]:
    # http.client never reads a body after HEAD, so a body sent anyway is only seen on the wire.
    with socket.create_connection(("127.0.0.1", running.server.http_port), timeout=5) as sock:
        sock.sendall(f"{method} {target} HTTP/1.0\r\n\r\n".encode())
        received = b""
        while chunk := sock.recv(4096):
            received += chunk
    head, separator, body = received.partition(b"\r\n\r\n")
    assert separator, received
    return head, body


def test_head_sends_no_body_on_the_wire(running):
    get_head, get_body = _raw(running, "GET", "/canary.html")
    head_head, head_body = _raw(running, "HEAD", "/canary.html")
    assert get_body == PAGE
    assert head_body == b""
    assert head_head.startswith(b"HTTP/1.0 200 ")

    def length(head: bytes) -> list[bytes]:
        return [
            line.split(b":", 1)[1].strip()
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"content-length:")
        ]

    assert length(head_head) == length(get_head) == [str(len(PAGE)).encode()]


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/../etc/passwd",
        "/%2e%2e/x",
        "/%63anary.html",
        "//canary.html",
        "///canary.html",
        "/canary.html/",
        "/CANARY.HTML",
        "/missing.html",
        "/sub",
        "/sub/",
        "/sub/inner.txt",
        "/link.txt",
        "http://fixture.test/canary.html",
    ],
)
def test_nothing_else_is_served(running, target):
    for method in ("GET", "HEAD"):
        response = running.request(method, target)
        assert response.status == 404, target
        assert response.getheader("Location") is None
        assert b"MCPB-CANARY" not in response.body
        assert b"outside" not in response.body


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "BREW"])
def test_other_methods_are_refused(running, method):
    response = running.request(method, "/canary.html")
    assert response.status in (405, 501)
    assert PAGE not in response.body


def test_query_string_does_not_change_the_name(running):
    assert running.request("GET", "/canary.html?x=1").body == PAGE
    assert running.request("GET", "/canary.html%3Fx=1").status == 404


def test_every_request_is_in_the_log(running):
    running.request("GET", "/canary.html", **{"User-Agent": "probe/1"})
    running.request("GET", "//canary.html")
    running.request("POST", "/notes.txt")
    events = running.events("http")
    assert [(e["method"], e["path"], e["status"]) for e in events] == [
        ("GET", "/canary.html", 200),
        ("GET", "//canary.html", 404),
        ("POST", "/notes.txt", 405),
    ]
    assert events[0]["user_agent"] == "probe/1"
    assert events[0]["client"] == "127.0.0.1"
    assert events[1]["user_agent"] is None  # http.client sends none


class _Named(int):
    """A status whose text is its name, as ``HTTPStatus`` is before Python 3.11."""

    def __str__(self) -> str:
        return "HTTPStatus.OK"


def test_the_status_in_the_log_is_the_number_in_every_version_of_python():
    assert fixture_server._status(_Named(200)) == 200
    assert fixture_server._status(fixture_server.HTTPStatus.METHOD_NOT_ALLOWED) == 405
    assert fixture_server._status("404") == 404
    assert fixture_server._status("-") is None
    assert fixture_server._status("\u0664") is None  # a digit, but not one int() should take here


def test_a_file_added_after_the_start_is_not_served(running, tmp_path):
    (tmp_path / "fixture" / "late.txt").write_bytes(b"late")
    (tmp_path / "fixture" / "notes.txt").write_bytes(b"changed")
    assert running.request("GET", "/late.txt").status == 404
    assert running.request("GET", "/notes.txt").body == NOTE


def test_connections_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(fixture_server, "MAX_CONNECTIONS", 2)
    (tmp_path / "a.txt").write_bytes(b"a")
    out = io.StringIO()
    server = fixture_server.FixtureServer(
        str(tmp_path), {}, host="127.0.0.1", http_port=0, dns_port=0, out=out
    )
    server.start()
    idle = []
    try:
        for _ in range(2):
            idle.append(socket.create_connection(("127.0.0.1", server.http_port), timeout=5))
        deadline = time.monotonic() + 5
        while server._http._slots._value > 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        with socket.create_connection(("127.0.0.1", server.http_port), timeout=5) as third:
            assert third.recv(100).startswith(b"HTTP/1.0 503")
        idle[0].close()
        deadline = time.monotonic() + 5
        while server._http._slots._value < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        connection = http.client.HTTPConnection("127.0.0.1", server.http_port, timeout=5)
        connection.request("GET", "/a.txt")
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        for sock in idle:
            sock.close()
        server.stop()


# -- DNS ----------------------------------------------------------------------------------


def test_dns_answers_a_for_a_known_name(running):
    for asked in ("fixture.test", "FIXTURE.test", "Fixture.Test."):
        reply = running.ask(asked)
        rcode, flags, answers, raw = _answer(reply)
        assert (rcode, answers) == (0, 1)
        assert flags & 0x8000 and flags & 0x0400 and flags & 0x0100  # QR, AA, RD copied
        assert raw[-4:] == socket.inet_aton(ADDRESS)
    events = running.events("dns")
    assert [e["name"] for e in events] == ["fixture.test", "FIXTURE.test", "Fixture.Test"]
    assert all(e["type"] == "A" and e["answer"] == ADDRESS for e in events)
    assert events[0]["client"] == "127.0.0.1"


def test_dns_answers_a_name_whose_last_label_ends_in_a_dot(running):
    # Labels are never empty, but a label may hold the byte "."; joined, the name ends in one.
    question = b"\x07fixture\x05test.\x00" + struct.pack("!HH", 1, 1)
    packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + question
    rcode, _flags, answers, raw = _answer(running.ask("", packet=packet))
    assert (rcode, answers) == (0, 1)
    assert raw[-4:] == socket.inet_aton(ADDRESS)
    (event,) = running.events("dns")
    assert event["name"] == "fixture.test." and event["answer"] == ADDRESS


def test_dns_known_name_other_type_is_noerror_without_answer(running):
    rcode, _flags, answers, _raw = _answer(running.ask("fixture.test", 28))
    assert (rcode, answers) == (0, 0)
    (event,) = running.events("dns")
    assert event["type"] == "AAAA" and event["answer"] is None


def test_dns_unknown_name_is_nxdomain(running):
    rcode, _flags, answers, _raw = _answer(running.ask("example.com"))
    assert (rcode, answers) == (3, 0)
    assert running.ask("fixture.test.example.com") is not None
    events = running.events("dns")
    assert [(e["name"], e["answer"]) for e in events] == [
        ("example.com", None),
        ("fixture.test.example.com", None),
    ]


def test_dns_ignores_what_is_not_a_question(running):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"\x07fixture\x04test\x00" + struct.pack("!HH", 1, 1)
    broken = [
        b"",
        b"\x00" * 5,
        header[:-1],
        header + question[:-3],  # cut inside the question
        header + b"\x40" + b"a" * 64 + b"\x00" + struct.pack("!HH", 1, 1),  # label too long
        header + b"\xc0\x0c" + struct.pack("!HH", 1, 1),  # compression pointer
        struct.pack("!HHHHHH", 1, 0x8100, 1, 0, 0, 0) + question,  # a response
        struct.pack("!HHHHHH", 1, 0x2800, 1, 0, 0, 0) + question,  # another opcode
        struct.pack("!HHHHHH", 1, 0x0100, 0, 0, 0, 0),  # no question
        struct.pack("!HHHHHH", 1, 0x0100, 2, 0, 0, 0) + question * 2,  # two questions
    ]
    for packet in broken:
        assert running.ask("", packet=packet) is None
    assert running.events("dns") == []
    # and the server still answers afterwards
    assert _answer(running.ask("fixture.test"))[2] == 1


def test_dns_has_no_forwarding_and_no_extra_records(running):
    # A packet with an EDNS record behind the question: answered, the record is not echoed.
    question = b"\x07fixture\x04test\x00" + struct.pack("!HH", 1, 1)
    packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 1) + question
    packet += b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
    reply = running.ask("", packet=packet)
    _rcode, _flags, answers, raw = _answer(reply)
    assert answers == 1
    assert struct.unpack("!HHHHHH", raw[:12])[5] == 0
    assert len(raw) == 12 + len(question) + 16


# -- the log ------------------------------------------------------------------------------


def test_log_limits_are_as_documented():
    assert (fixture_server.MAX_LOGGED_EVENTS, fixture_server.DROPPED_EVERY) == (2000, 1000)


def test_under_the_limit_every_event_is_written(running):
    for _ in range(fixture_server.MAX_LOGGED_EVENTS // 2):
        running.server.log({"event": "http"})
        running.server.log({"event": "dns"})
    assert running.events()[0]["event"] == "ready"
    assert len(running.events("http")) == len(running.events("dns")) == 1000
    assert running.events("dropped") == []


def test_over_the_limit_events_are_only_counted(running):
    # The ready line is already written and does not count against the limit.
    for _ in range(fixture_server.MAX_LOGGED_EVENTS):
        running.server.log({"event": "http"})
    for _ in range(300):
        running.server.log({"event": "http"})
    for _ in range(1700):
        running.server.log({"event": "dns"})
    for _ in range(999):
        running.server.log({"event": "http"})
    assert len(running.events("http")) == 2000
    assert running.events("dns") == []
    assert running.events("dropped") == [
        {"event": "dropped", "http": 300, "dns": 700},
        {"event": "dropped", "http": 300, "dns": 1700},
    ]
    running.server.log({"event": "dns"})
    assert running.events("dropped")[-1] == {"event": "dropped", "http": 1299, "dns": 1701}
    assert len(running.events()) == 1 + 2000 + 3


def test_the_limit_holds_for_real_requests_and_questions(running, monkeypatch):
    monkeypatch.setattr(fixture_server, "MAX_LOGGED_EVENTS", 2)
    monkeypatch.setattr(fixture_server, "DROPPED_EVERY", 2)
    for _ in range(3):
        running.request("GET", "/canary.html")
        assert running.ask("fixture.test") is not None
    assert [e["event"] for e in running.events()] == ["ready", "http", "dns", "dropped", "dropped"]
    assert running.events("dropped") == [
        {"event": "dropped", "http": 1, "dns": 1},
        {"event": "dropped", "http": 2, "dns": 2},
    ]


def test_main_refuses_a_name_without_an_address(capsys):
    with pytest.raises(SystemExit):
        fixture_server.main(["--name", "fixture.test"])
    # The usage line names the metavar NAME=IPV4 anyway; the error line itself must name it.
    (error,) = [line for line in capsys.readouterr().err.splitlines() if "error:" in line]
    assert "expected NAME=IPV4" in error and "'fixture.test'" in error
