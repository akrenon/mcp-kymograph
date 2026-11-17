"""The channel and the driver in the two generations, against stubs that say exactly what a test
needs: how the probe is answered, what the heads of the modern requests are, and when a legacy
stream is resumed.

The end-to-end runs against the fixture server are in ``test_era_opening.py``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json

import pytest

from mcp_kymograph import eras
from mcp_kymograph.driver import DISCOVERY, Driver, Opening
from mcp_kymograph.http_client import HttpClientChannel, _header_value, _sendable_id
from test_http_client import http, stub

__all__ = ["stub"]  # a fixture of test_http_client, used here

STEP_TIMEOUT = 5.0
CLIENT = {"name": "mcp-kymograph", "version": "test"}


def message_of(seen) -> dict:
    """The JSON-RPC message a stub was sent; none for a GET or a DELETE."""
    return json.loads(seen.body) if seen.body else {}


def answer(identifier, **result) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": identifier, "result": result}).encode()


def refusal(code, identifier=None, **data) -> bytes:
    error = {"code": code, "message": "x", **({"data": data} if data else {})}
    return json.dumps({"jsonrpc": "2.0", "id": identifier, "error": error}).encode()


def server(probe, *, tools=True):
    """A stub's reply: ``probe(seen)`` answers ``server/discover``; ``initialize`` is answered in
    2025-06-18 with a session; a listing with no tools; a notification with 202."""

    def reply(connection, seen):
        message = message_of(seen)
        method = message.get("method")
        if method == "server/discover":
            connection.sendall(probe(seen, message))
        elif method == "initialize":
            caps = {"tools": {}} if tools else {}
            body = answer(
                message["id"],
                protocolVersion=message["params"]["protocolVersion"],
                capabilities=caps,
            )
            connection.sendall(http(200, body, extra="Mcp-Session-Id: s1\r\n"))
        elif "id" in message:
            connection.sendall(http(200, answer(message["id"], tools=[])))
        else:
            connection.sendall(http(202))

    return reply


class Recorded:
    def __init__(self) -> None:
        self.era: list[dict] = []
        self.failed: list[dict] = []
        self.finished: list[dict] = []
        self.reissued: list[dict] = []
        self.skipped: list[dict] = []
        self.unanswered: list[dict] = []

    def into(self, where: str):
        async def record(**fields) -> None:
            getattr(self, where).append(fields)

        return record


def drive(url: str, *, opening=None, request_version=eras.LEGACY_REQUEST_VERSION, declared=None):
    seen = Recorded()
    channel = HttpClientChannel(url, connect_timeout=STEP_TIMEOUT)
    driver = Driver(
        DISCOVERY,
        channel,
        record_skipped=seen.into("skipped"),
        record_failed=seen.into("failed"),
        record_unanswered=seen.into("unanswered"),
        record_finished=seen.into("finished"),
        record_era=seen.into("era"),
        record_reissued=seen.into("reissued"),
        opening=opening or Opening(request_version=request_version, declared=declared),
        step_timeout=STEP_TIMEOUT,
    )
    outcome = asyncio.run(driver.run())
    return outcome, seen


# -- a probe that is not answered as a modern server would ------------------------------------


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (404, b"", "application/json"),
        (404, b"<html>not here</html>", "text/html"),
        (405, b"", "application/json"),
        (200, b"", "application/json"),
        (200, b"this is not json", "application/json"),
        (400, b"", "application/json"),
        (400, b"plain text", "text/plain"),
        (400, b"not json either", "application/json"),
        (500, json.dumps({"hello": "world"}).encode(), "application/json"),
    ],
)
def test_a_probe_not_answered_with_a_json_rpc_message_is_legacy_and_initialize_follows(
    stub,
    status,
    body,
    kind,
):
    handled = stub(server(lambda seen, message: http(status, body, kind=kind)))

    outcome, seen = drive(handled.url)

    assert outcome.era == "legacy" and outcome.server_failed is None
    assert [r.body and json.loads(r.body).get("method") for r in handled.requests][:2] == [
        "server/discover",
        "initialize",
    ]
    (decided,) = seen.era
    assert decided["probe"]["outcome"] in (eras.NOT_JSON_RPC, "other_error", "other_result")
    assert (decided["era"], decided["outcome"]) == ("legacy", "proceed")


def test_the_body_of_a_400_is_read_and_a_modern_refusal_with_a_null_id_stops_the_run(
    stub,
):
    body = refusal(-32021, None, requiredCapabilities={"sampling": {}})
    handled = stub(server(lambda seen, message: http(400, body)))

    outcome, seen = drive(handled.url)

    assert outcome.server_failed == "protocol_unsupported"
    assert outcome.stop["required"] == ["sampling"] and outcome.stop["code"] == -32021
    assert outcome.inventory == "none" and outcome.era == "modern"
    (decided,) = seen.era
    assert (decided["outcome"], decided["reason"]) == ("stop", "modern_refused")
    assert decided["refusal"] == {
        "code": -32021,
        "data": {"requiredCapabilities": {"sampling": {}}},
    }
    assert [json.loads(r.body).get("method") for r in handled.requests] == ["server/discover"]
    assert seen.failed[0]["reason"] == "protocol_unsupported"


def test_a_400_naming_a_legacy_version_sends_that_versions_initialize(stub):
    body = refusal(-32022, 1, supported=["2025-06-18", "2025-11-25"])
    handled = stub(server(lambda seen, message: http(400, body)))

    outcome, seen = drive(handled.url, request_version="2025-11-25")

    (initialize,) = [json.loads(r.body) for r in handled.requests if b'"initialize"' in r.body]
    assert initialize["params"]["protocolVersion"] == "2025-11-25"
    assert (outcome.era, outcome.protocol_version) == ("legacy", "2025-11-25")


def test_a_probe_that_times_out_is_legacy_after_the_wait(stub):
    def silent(connection, seen):
        message = message_of(seen)
        if message.get("method") == "server/discover":
            connection.settimeout(3)
            with contextlib.suppress(OSError):
                connection.recv(1)  # hold the connection open until the client gives up
            return
        server(None)(connection, seen)

    handled = stub(silent)
    seen = Recorded()
    channel = HttpClientChannel(handled.url, connect_timeout=2)
    driver = Driver(
        DISCOVERY,
        channel,
        record_skipped=seen.into("skipped"),
        record_failed=seen.into("failed"),
        record_era=seen.into("era"),
        opening=Opening(),
        step_timeout=0.4,
    )
    outcome = asyncio.run(driver.run())

    assert seen.era[0]["probe"]["outcome"] == "no_answer"
    assert (outcome.era, outcome.server_failed) == ("legacy", None)


def test_an_endpoint_that_cannot_be_reached_ends_on_the_probe_with_no_decision():
    outcome, seen = drive("http://127.0.0.1:1/mcp")

    assert outcome.server_failed == "http_unreachable"
    assert seen.era == [] and seen.failed[0]["reason"] == "http_unreachable"


def test_a_401_to_the_probe_ends_the_run_as_unauthorized_and_decides_nothing(stub):
    handled = stub(
        server(lambda seen, message: http(401, b"", extra="WWW-Authenticate: Bearer\r\n"))
    )

    outcome, seen = drive(handled.url)

    assert outcome.server_failed == "unauthorized" and seen.era == []


def test_an_empty_200_to_the_probe_is_not_a_stream_that_broke(stub):
    handled = stub(server(lambda seen, message: http(200, b"")))

    outcome, _ = drive(handled.url)

    assert outcome.server_failed is None and outcome.era == "legacy"


# -- the heads of a modern request ------------------------------------------------------------


async def one_request(url: str, message: dict) -> None:
    channel = HttpClientChannel(url, connect_timeout=STEP_TIMEOUT)
    await channel.send(json.dumps(message).encode() + b"\n")
    with contextlib.suppress(asyncio.TimeoutError):
        await channel.read_line(1)
    channel.close()


def meta() -> dict:
    return eras.meta(CLIENT, {})


@pytest.mark.parametrize(
    ("method", "params", "name"),
    [
        ("tools/list", {}, None),
        ("tools/call", {"name": "tool_0", "arguments": {}}, "tool_0"),
        ("prompts/get", {"name": "greet"}, "greet"),
        ("resources/read", {"uri": "file:///data/report.txt"}, "file:///data/report.txt"),
        (
            "resources/read",
            {"uri": "file:///data/a b.txt"},
            "=?base64?" + base64.b64encode(b"file:///data/a b.txt").decode() + "?=",
        ),
    ],
)
def test_a_modern_request_names_its_version_its_method_and_where_it_applies_its_object(
    stub,
    method,
    params,
    name,
):
    handled = stub(lambda connection, seen: connection.sendall(http(200, answer(1, tools=[]))))
    message = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": meta()}}

    asyncio.run(one_request(handled.url, message))

    (seen,) = handled.requests
    assert seen.headers["mcp-protocol-version"] == "2026-07-28"
    assert seen.headers["mcp-method"] == method
    assert seen.headers.get("mcp-name") == name
    assert "mcp-session-id" not in seen.headers


def test_a_legacy_request_has_none_of_the_modern_headers(stub):
    handled = stub(lambda connection, seen: connection.sendall(http(200, answer(2, tools=[]))))
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}

    asyncio.run(one_request(handled.url, message))

    (seen,) = handled.requests
    assert not {"mcp-method", "mcp-name"} & set(seen.headers)


@pytest.mark.parametrize(
    ("value", "sent"),
    [
        ("tool_0", "tool_0"),
        ("two words", "=?base64?" + base64.b64encode(b"two words").decode() + "?="),
        (" leading", "=?base64?" + base64.b64encode(b" leading").decode() + "?="),
        ("trailing ", "=?base64?" + base64.b64encode(b"trailing ").decode() + "?="),
        ("naïve", "=?base64?" + base64.b64encode("naïve".encode()).decode() + "?="),
        (
            "a\r\nX-Injected: 1",
            "=?base64?" + base64.b64encode(b"a\r\nX-Injected: 1").decode() + "?=",
        ),
        ("", "=?base64??="),
        ("=?base64?abc?=", "=?base64?" + base64.b64encode(b"=?base64?abc?=").decode() + "?="),
    ],
)
def test_a_name_outside_visible_ascii_is_sent_as_base64_and_never_as_a_second_header(value, sent):
    assert _header_value(value) == sent
    assert "\r" not in sent and "\n" not in sent


def test_a_version_in_meta_that_is_not_a_version_makes_the_request_a_legacy_one(stub):
    handled = stub(lambda connection, seen: connection.sendall(http(200, answer(1, tools=[]))))
    bad = {eras.META_VERSION: "2026-07-28\r\nX-Evil: 1"}
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": bad}}

    asyncio.run(one_request(handled.url, message))

    (seen,) = handled.requests
    assert "x-evil" not in seen.headers and "mcp-method" not in seen.headers


# -- a modern stream that breaks --------------------------------------------------------------


def broken_listing(connection, seen):
    message = message_of(seen)
    if "method" not in message:  # a reply or notification of the client
        connection.sendall(http(202))
    elif message["method"] == "server/discover":
        result = answer(
            message["id"],
            supportedVersions=["2026-07-28"],
            capabilities={"tools": {}},
        )
        connection.sendall(http(200, result))
    else:
        body = answer(message["id"], tools=[])
        head = (
            f"HTTP/1.1 200 X\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n"
        )
        connection.sendall((head + "Connection: close\r\n\r\n").encode() + body[: len(body) // 2])


def test_a_modern_listing_whose_body_ends_early_is_asked_for_once_more_and_then_is_broken(
    stub,
):
    handled = stub(broken_listing)

    outcome, seen = drive(handled.url)

    methods = [json.loads(r.body)["method"] for r in handled.requests]
    assert methods == ["server/discover", "tools/list", "tools/list"]
    assert seen.reissued == [{"step": "tools/list", "page": 0, "reason": "stream_broken"}]
    assert [(u["step"], u["reason"]) for u in seen.unanswered] == [("tools/list", "stream_broken")]
    ids = [json.loads(r.body)["id"] for r in handled.requests]
    assert len(set(ids)) == 3
    assert outcome.inventory == "partial"


def test_a_head_with_no_body_at_all_in_the_modern_era_is_broken_too(stub):
    def reply(connection, seen):
        message = message_of(seen)
        if "method" not in message:  # a reply or notification of the client
            connection.sendall(http(202))
        elif message["method"] == "server/discover":
            body = answer(
                message["id"], supportedVersions=["2026-07-28"], capabilities={"tools": {}}
            )
            connection.sendall(http(200, body))
        else:
            connection.sendall(http(200, b""))

    handled = stub(reply)

    outcome, seen = drive(handled.url)

    assert [u["reason"] for u in seen.unanswered] == ["stream_broken"] and len(seen.reissued) == 1


def test_an_answer_too_large_to_read_is_unreadable_not_a_broken_stream(stub):
    def reply(connection, seen):
        message = message_of(seen)
        if "method" not in message:  # a reply or notification of the client
            connection.sendall(http(202))
        elif message["method"] == "server/discover":
            body = answer(
                message["id"], supportedVersions=["2026-07-28"], capabilities={"tools": {}}
            )
            connection.sendall(http(200, body))
        else:
            connection.sendall(http(200, b"{not json at all"))

    handled = stub(reply)

    outcome, seen = drive(handled.url)

    assert seen.reissued == []
    assert [u["reason"] for u in seen.unanswered] == ["answer_unreadable"]


# -- a legacy stream that is resumed ----------------------------------------------------------


def sse(*events: str) -> bytes:
    body = "".join(events).encode()
    return b"HTTP/1.1 200 X\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n" + body


def resumable(event_id: str):
    asked = []

    def reply(connection, seen):
        if seen.method == "GET":
            body = answer(asked[-1], tools=[{"name": "t"}])
            connection.sendall(sse(f"id: {event_id}b\nevent: message\ndata: {body.decode()}\n\n"))
            return
        message = message_of(seen)
        if "method" not in message:  # a reply or notification of the client
            connection.sendall(http(202))
        elif message.get("method") == "server/discover":
            connection.sendall(http(404))
        elif message.get("method") == "initialize":
            body = answer(message["id"], protocolVersion="2025-11-25", capabilities={"tools": {}})
            connection.sendall(http(200, body, extra="Mcp-Session-Id: s1\r\n"))
        elif "id" in message:
            asked.append(message["id"])
            connection.sendall(sse(f"id: {event_id}\nretry: 10\ndata:\n\n"))
        else:
            connection.sendall(http(202))

    return reply


def test_a_legacy_stream_closed_after_an_event_id_is_resumed_with_the_ids_and_the_session(
    stub,
):
    handled = stub(resumable("evt-1"))

    outcome, seen = drive(handled.url, request_version="2025-11-25")

    (resume,) = [r for r in handled.requests if r.method == "GET"]
    assert resume.headers["last-event-id"] == "evt-1"
    assert resume.headers["mcp-session-id"] == "s1"
    assert resume.headers["mcp-protocol-version"] == "2025-11-25"
    assert resume.headers["accept"] == "text/event-stream"
    assert seen.unanswered == [] and outcome.inventory == "complete"


@pytest.mark.parametrize("event_id", ["has space", "x" * 2000, "tab\there"])
def test_an_event_id_that_cannot_be_sent_back_as_a_header_is_not_sent_and_the_stream_is_broken(
    stub,
    event_id,
):
    handled = stub(resumable(event_id))

    outcome, seen = drive(handled.url, request_version="2025-11-25")

    assert [r for r in handled.requests if r.method == "GET"] == []
    assert [u["reason"] for u in seen.unanswered] == ["stream_broken"]


@pytest.mark.parametrize(
    ("value", "ok"),
    [("evt-1", True), ("a" * 1024, True), ("a" * 1025, False), ("", False), (None, False),
     ("a b", False), ("a\r\nb", False), ("é", False)],
)  # fmt: skip
def test_only_visible_ascii_of_a_bounded_length_goes_back_in_last_event_id(value, ok):
    assert _sendable_id(value) is ok


def test_a_stream_without_an_event_id_is_not_resumed_and_ends_as_it_always_did(stub):
    def reply(connection, seen):
        message = message_of(seen)
        if "method" not in message:  # a reply or notification of the client
            connection.sendall(http(202))
        elif message["method"] == "server/discover":
            connection.sendall(http(404))
        elif message["method"] == "initialize":
            body = answer(message["id"], protocolVersion="2025-06-18", capabilities={"tools": {}})
            connection.sendall(http(200, body, extra="Mcp-Session-Id: s1\r\n"))
        elif "id" in message:
            connection.sendall(sse("data:\n\n"))
        else:
            connection.sendall(http(202))

    handled = stub(reply)

    outcome, seen = drive(handled.url)

    assert [r for r in handled.requests if r.method == "GET"] == []
    assert [u["reason"] for u in seen.unanswered] == ["connection_closed"]
