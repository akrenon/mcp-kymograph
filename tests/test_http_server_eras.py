"""The generations of the HTTP test server (``--era``, ``--versions``, ``--refuse``,
``--break-stream``, ``--close-early``), against itself only.

The modern side is this repository's reading of 2026-07-28: these tests say what the fixture does,
so that the tests that drive it say what they mean; they do not vouch for a real modern server.
"""

from __future__ import annotations

import http.client
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_http_server import ACCEPT, Client, answer

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
MODERN_HEADS = {"MCP-Protocol-Version": "2026-07-28"}


@pytest.fixture
def start():
    servers = []

    def started(**behaviour):
        server = http_server.serve(**behaviour)
        servers.append(server)
        return Client(server.server_address[1]), server

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


def modern(client: Client, method: str, params: dict | None = None, *, name=None, **headers):
    """A request of the modern era as a conforming client sends it."""
    meta = {VERSION_KEY: "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}
    sent = {**MODERN_HEADS, "Mcp-Method": method, **headers}
    if name is not None:
        sent["Mcp-Name"] = name
    return client.request(method, {**(params or {}), "_meta": meta}, headers=sent)


def body_of(response) -> dict:
    status, headers, data = response
    return answer(headers, data)


# -- the three eras --------------------------------------------------------------------------


def test_a_legacy_server_answers_the_probe_with_a_400_and_no_modern_error(start):
    client, _ = start()

    status, _, data = modern(client, "server/discover")

    assert status == 400
    assert json.loads(data)["error"]["code"] == -32600  # not a modern error: the probe reads legacy


def test_a_modern_server_answers_the_probe_with_a_discover_result(start):
    client, _ = start(era="modern")

    result = body_of(modern(client, "server/discover"))["result"]

    assert result["supportedVersions"] == ["2026-07-28"]
    assert result["resultType"] == "complete"
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "reference-server"
    assert "tools" in result["capabilities"]


def test_a_dual_server_names_both_eras_and_serves_both(start):
    client, _ = start(era="dual", versions=("2025-06-18", "2025-11-25"))

    listed = body_of(modern(client, "server/discover"))["result"]["supportedVersions"]
    assert listed == ["2026-07-28", "2025-06-18", "2025-11-25"]
    assert body_of(modern(client, "tools/list"))["result"]["tools"]
    assert client.initialize()["result"]["protocolVersion"] == "2025-06-18"  # the legacy side


def test_the_versions_a_probe_answer_lists_can_be_set(start):
    client, _ = start(era="dual", discover_lists=("2025-11-25",))

    listed = body_of(modern(client, "server/discover"))["result"]["supportedVersions"]

    assert listed == ["2025-11-25"]


def test_modern_listings_keep_the_legacy_shapes_and_need_no_session(start):
    client, _ = start(era="modern")

    result = body_of(modern(client, "tools/list"))["result"]

    assert result["tools"][0]["name"] == "tool_0" and set(result) == {"tools"}
    assert client.session is None


def test_a_modern_only_server_refuses_what_has_no_modern_headers(start):
    client, _ = start(era="modern")

    status, _, data = client.request(
        "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {}}
    )

    assert status == 400
    error = json.loads(data)["error"]
    assert error["code"] == -32602 and "2026-07-28" in error["message"]


# -- the headers it holds a modern request to ------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "words"),
    [
        ({"Mcp-Method": "tools/call"}, "Mcp-Method"),
        ({"Mcp-Method": None}, "Mcp-Method"),
    ],
)
def test_a_method_header_that_disagrees_with_the_body_is_a_header_mismatch(start, headers, words):
    client, _ = start(era="modern")
    meta = {VERSION_KEY: "2026-07-28"}
    sent = {**MODERN_HEADS, **{k: v for k, v in headers.items() if v is not None}}

    status, _, data = client.request("tools/list", {"_meta": meta}, headers=sent)

    error = json.loads(data)["error"]
    assert (status, error["code"], json.loads(data)["id"]) == (400, -32020, None)
    assert words in error["message"]


def test_a_meta_version_that_disagrees_with_the_header_is_a_header_mismatch(start):
    client, _ = start(era="modern")

    status, _, data = client.request(
        "tools/list",
        {"_meta": {VERSION_KEY: "2025-11-25"}},
        headers={**MODERN_HEADS, "Mcp-Method": "tools/list"},
    )

    assert (status, json.loads(data)["error"]["code"]) == (400, -32020)


def test_a_call_without_its_name_header_is_a_header_mismatch_and_with_it_is_answered(start):
    client, _ = start(era="modern", call_result="text")
    params = {"name": "tool_0", "arguments": {}}

    refused = modern(client, "tools/call", params)
    served = modern(client, "tools/call", params, name="tool_0")

    assert json.loads(refused[2])["error"]["code"] == -32020
    assert served[0] == 200 and "result" in body_of(served)


def test_get_and_delete_are_405_in_the_modern_era(start):
    _, server = start(era="modern")
    port = server.server_address[1]

    for method in ("GET", "DELETE"):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request(method, http_server.PATH, headers=MODERN_HEADS)
        assert connection.getresponse().status == 405
        connection.close()


def test_the_requests_are_kept_with_the_headers_that_name_a_generation(start):
    client, server = start(era="dual")

    modern(client, "tools/list")
    client.initialize()

    first, second = server.behaviour.heads
    assert (first["method"], first["version"], first["mcp_method"]) == (
        "POST",
        "2026-07-28",
        "tools/list",
    )
    assert (second["version"], second["mcp_method"], second["session"]) == (None, None, None)


# -- what it refuses on request ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "data"),
    [
        (-32021, {"requiredCapabilities": {"elicitation": {}}}),
        (-32022, {"supported": ["2026-07-28"]}),
        (-32020, None),
        (-32000, None),
    ],
)
def test_a_server_can_refuse_every_modern_request_with_a_code(start, code, data):
    client, _ = start(era="modern", refuse=code)

    status, _, body = modern(client, "server/discover")

    error = json.loads(body)["error"]
    assert (status, error["code"], error.get("data")) == (400, code, data)


def test_refusing_and_listing_versions_are_for_a_server_with_a_modern_side():
    with pytest.raises(ValueError):
        http_server.Behaviour(refuse=-32021)
    with pytest.raises(ValueError):
        http_server.Behaviour(discover_lists=("2026-07-28",))


# -- the legacy versions -------------------------------------------------------------------------


def test_initialize_is_answered_with_the_version_asked_for_if_the_server_has_it(start):
    client, _ = start(versions=("2025-06-18", "2025-11-25"))

    status, headers, body = client.request(
        "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}}
    )

    assert status == 200 and answer(headers, body)["result"]["protocolVersion"] == "2025-11-25"
    client.session = headers["mcp-session-id"]
    ok = client.request("tools/list", headers={"MCP-Protocol-Version": "2025-11-25"})
    assert ok[0] == 200


def test_initialize_is_answered_with_the_newest_it_has_when_asked_for_another(start):
    client, _ = start(versions=("2025-06-18",))

    _, headers, body = client.request(
        "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}}
    )

    assert answer(headers, body)["result"]["protocolVersion"] == "2025-06-18"


def test_a_strict_server_refuses_another_version_and_lists_its_own(start):
    client, _ = start(versions=("2025-06-18",), strict_version=True)

    _, headers, body = client.request(
        "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {}}
    )

    error = answer(headers, body)["error"]
    assert (error["code"], error["data"]["supported"]) == (-32602, ["2025-06-18"])


def test_a_version_header_the_server_does_not_support_is_still_a_400(start):
    client, _ = start(versions=("2025-06-18",))
    client.initialize()

    status, _, _ = client.request("tools/list", headers={"MCP-Protocol-Version": "2025-11-25"})

    assert status == 400


# -- a stream that breaks, and one closed early -------------------------------------------------


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_the_first_n_answers_of_the_method_are_cut_and_the_next_one_is_whole(start, respond):
    client, server = start(era="modern", respond=respond, break_stream=2)

    cut = [modern(client, "tools/list") for _ in range(2)]
    whole = modern(client, "tools/list")

    for _, headers, body in cut:
        with pytest.raises((ValueError, AssertionError)):
            answer(headers, body)
    assert whole[0] == 200 and body_of(whole)["result"]["tools"]
    assert server.behaviour.broken == 2


def test_a_stream_closed_early_gives_an_id_and_the_answer_waits_for_a_get(start):
    client, server = start(respond="stream", close_early="once")
    client.initialize()

    status, headers, body = client.request("tools/list")
    assert status == 200 and body.startswith(b"id: e1-0\nretry: 10\ndata:\n\n")

    connection = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    connection.request(
        "GET",
        http_server.PATH,
        headers={"Last-Event-ID": "e1-0", "Mcp-Session-Id": client.session, "Accept": ACCEPT},
    )
    response = connection.getresponse()
    text = response.read().decode()
    connection.close()
    assert response.status == 200 and '"tools"' in text and text.startswith("id: e1-0-answer")


def test_with_always_the_resumption_brings_another_event_and_never_the_answer(start):
    client, _ = start(respond="stream", close_early="always")
    client.initialize()
    client.request("tools/list")

    connection = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    connection.request(
        "GET",
        http_server.PATH,
        headers={"Last-Event-ID": "e1-0", "Mcp-Session-Id": client.session, "Accept": ACCEPT},
    )
    text = connection.getresponse().read().decode()
    connection.close()

    assert text.startswith("id: e1-1\nretry: 10") and '"tools"' not in text


def test_a_get_without_an_id_the_server_gave_is_405(start):
    client, _ = start(respond="stream", close_early="once")
    client.initialize()

    connection = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    connection.request(
        "GET",
        http_server.PATH,
        headers={"Last-Event-ID": "unknown", "Mcp-Session-Id": client.session},
    )
    assert connection.getresponse().status == 405
    connection.close()


# -- the command line -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        ["--era", "ancient"],
        ["--close-early", "once"],  # needs --respond stream
        ["--refuse", "-32021"],  # needs a modern side
        ["--break-stream", "-1"],
    ],
)
def test_a_misspelt_choice_is_refused_at_start(arguments):
    run = subprocess.run(  # noqa: S603
        [sys.executable, str(FIXTURES / "http_server.py"), *arguments],
        capture_output=True,
        timeout=20,
        check=False,
    )

    assert run.returncode == 2


def test_the_command_line_starts_a_server_of_the_era_asked_for():
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            str(FIXTURES / "http_server.py"),
            "--era",
            "modern",
            "--versions",
            "2025-11-25",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        url = process.stdout.readline().strip()
        port = int(url.rsplit(":", 1)[1].split("/")[0])
        status, _, data = modern(Client(port), "server/discover")
        assert status == 200
        assert json.loads(data)["result"]["supportedVersions"] == ["2026-07-28"]
    finally:
        process.kill()
        process.wait()
