"""The opening of a driven run: which generation of the protocol the server speaks, and speaking it.

Through ``cli.main``, against the fixture server over HTTP on loopback (``--era legacy``,
``modern`` and ``dual``, the versions it supports, what it refuses) and against the stdio fixtures
of ``tests/fixtures/eras``. The modern side of the HTTP fixture is this repository's reading of
2026-07-28, not a reference server, and these tests say what that reading is — they do not
vouch for a real one.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, eras
from mcp_kymograph.inspection import Inspector
from test_cli_engagement import events_of, recording_in, write_engagement
from test_inspection import look_at

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ERA_SERVERS = FIXTURES / "eras"
#: An engagement whose script may call tools (the gate asks, for a script that does).
CALLS = {"list": True, "call": True}
CALL = """\
version: 1
name: probe
steps:
  - initialize
  - list: tools/list
  - call:
      tool: tool_0
      arguments: {text: "one"}
"""


@pytest.fixture
def serve():
    started = []

    def start(**behaviour):
        server = http_server.serve(**behaviour)
        started.append(server)
        return server

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def url_of(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"


def drive(tmp_path, server, *extra, engaged=False, **changes):
    """``drive --http`` against a fixture server, with or without an engagement file (whose
    ``changes`` replace its keys): the exit code and the recording's events."""
    out = tmp_path / "runs"
    args = ["drive", "--http", url_of(server), "--out-dir", str(out), "--step-timeout", "5"]
    if engaged or changes:
        args += ["--engagement", str(write_engagement(tmp_path / "engagement", **changes))]
    code = cli.main([*args, *extra])
    return code, events_of(recording_in(out))


def drive_stdio(tmp_path, fixture, *server_args, engaged=False):
    out = tmp_path / "runs"
    args = ["drive", "--out-dir", str(out), "--step-timeout", "5"]
    if engaged:
        args += ["--engagement", str(write_engagement(tmp_path / "engagement"))]
    command = [sys.executable, str(ERA_SERVERS / fixture), *server_args]
    code = cli.main([*args, "--", *command])
    return code, events_of(recording_in(out))


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def sent(events) -> list[str]:
    return [
        e["parse"]["method"]
        for e in events
        if e["type"] == "message" and e["direction"] == "client_to_server"
    ]


def decided(events) -> dict:
    (found,) = of(events, "era_decided")
    return found


def asked_version(events) -> str:
    (initialize,) = [
        e
        for e in of(events, "message")
        if e["direction"] == "client_to_server" and e["parse"]["method"] == "initialize"
    ]
    return initialize["payload"]["data"]["params"]["protocolVersion"]


def without_time(event: dict) -> dict:
    return {k: v for k, v in event.items() if k not in ("run_id", "seq", "t_ns")}


# -- a legacy server -------------------------------------------------------------------------


def test_a_legacy_server_is_probed_and_then_asked_initialize(serve, tmp_path):
    server = serve()

    code, events = drive(tmp_path, server)

    assert code == 0
    assert sent(events) == [
        "server/discover",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    found = decided(events)
    assert (found["era"], found["version"], found["outcome"]) == ("legacy", "2025-06-18", "proceed")
    assert found["probe"]["outcome"] == "other_error" and found["probe"]["code"] == -32600
    assert found["exchanges"] == [
        ["server/discover", "other_error", -32600],
        ["initialize", "other_result", None],
    ]
    assert found["declared"] is None and found["differs"] is None
    (end,) = of(events, "script_finished")
    assert (end["era"], end["protocol_version"]) == ("legacy", "2025-06-18")
    assert asked_version(events) == "2025-06-18"  # without an engagement: the driver's own


def test_the_probe_carries_the_modern_version_method_and_meta_and_nothing_a_legacy_server_keeps(
    serve, tmp_path
):
    server = serve()

    _, events = drive(tmp_path, server)

    probe, initialize, *_ = of(events, "http_request")
    assert probe["headers"]["mcp-protocol-version"] == "2026-07-28"
    assert probe["headers"]["mcp-method"] == "server/discover"
    assert "mcp-session-id" not in probe["headers"]
    assert "mcp-protocol-version" not in initialize["headers"]  # nothing negotiated yet
    (message,) = [m for m in of(events, "message") if m["parse"]["method"] == "server/discover"]
    meta = message["payload"]["data"]["params"]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
    assert meta["io.modelcontextprotocol/clientCapabilities"] == {}


def test_the_same_server_twice_gives_the_same_decision(serve, tmp_path):
    server = serve(era="dual", versions=("2025-06-18", "2025-11-25"))

    _, first = drive(tmp_path / "one", server)
    _, second = drive(tmp_path / "two", server)

    assert without_time(decided(first)) == without_time(decided(second))


# -- the legacy versions: 2025-11-25 under an engagement --------------------------------------


def test_a_server_of_2025_06_18_and_2025_11_25_is_asked_for_the_newer_under_an_engagement(
    serve, tmp_path
):
    server = serve(versions=("2025-06-18", "2025-11-25"))

    code, events = drive(tmp_path, server, engaged=True)

    assert code == 0 and asked_version(events) == "2025-11-25"
    assert (decided(events)["era"], decided(events)["version"]) == ("legacy", "2025-11-25")
    assert of(events, "script_finished")[0]["protocol_version"] == "2025-11-25"
    # The version negotiated is the one every later request names.
    later = [h for h in server.behaviour.heads if h["method"] == "POST"][2:]
    assert {h["version"] for h in later} == {"2025-11-25"}


def test_a_server_of_2025_06_18_only_is_spoken_to_in_it_under_an_engagement(serve, tmp_path):
    server = serve(versions=("2025-06-18",))

    code, events = drive(tmp_path, server, engaged=True)

    assert code == 0 and asked_version(events) == "2025-11-25"  # asked for the newest known
    assert (decided(events)["era"], decided(events)["version"]) == ("legacy", "2025-06-18")


def test_a_server_that_refuses_the_newer_version_is_asked_once_more_for_the_older(serve, tmp_path):
    server = serve(versions=("2025-06-18",), strict_version=True)

    code, events = drive(tmp_path, server, engaged=True)

    assert code == 0
    assert sent(events).count("initialize") == 2
    found = decided(events)
    assert found["version"] == "2025-06-18"
    assert [x[:2] for x in found["exchanges"]] == [
        ["server/discover", "other_error"],
        ["initialize", "other_error"],
        ["initialize", "other_result"],
    ]


def test_without_an_engagement_the_driver_keeps_asking_for_2025_06_18(serve, tmp_path):
    server = serve(versions=("2025-06-18", "2025-11-25"))

    _, events = drive(tmp_path, server)

    assert asked_version(events) == "2025-06-18"
    assert decided(events)["version"] == "2025-06-18"


def test_a_resumed_legacy_stream_brings_the_answer(serve, tmp_path):
    """2025-11-25 lets a server close the connection after an event id and the client resume
    with a GET and Last-Event-ID, waiting for ``retry``; the answer arrives on the second stream."""
    server = serve(respond="stream", close_early="once")

    code, events = drive(tmp_path, server, engaged=True)

    assert code == 0
    gets = [h for h in server.behaviour.heads if h["method"] == "GET"]
    assert [h["last_event_id"] for h in gets] == ["e1-0"]
    assert {h["session"] for h in gets} == {"yes"} and gets[0]["version"] == "2025-06-18"
    assert of(events, "script_finished")[0]["inventory"] == "complete"
    resumed = [e for e in of(events, "http_request") if e["method"] == "GET"]
    assert len(resumed) == 1 and "last-event-id" in resumed[0]["headers"]


def test_a_legacy_stream_that_is_resumed_three_times_without_the_answer_is_broken(serve, tmp_path):
    server = serve(respond="stream", close_early="always")

    code, events = drive(tmp_path, server)

    assert code == cli.EXIT_INCOMPLETE
    assert len([h for h in server.behaviour.heads if h["method"] == "GET"]) == 3
    ((step, pages, reason),) = [
        (e["step"], e["pages"], e["reason"]) for e in of(events, "step_unanswered")
    ]
    assert (step, pages, reason) == ("tools/list", 0, "stream_broken")
    assert of(events, "step_reissued") == []  # legacy resumes; it does not ask again
    assert of(events, "script_finished")[0]["inventory"] == "partial"


# -- a modern server --------------------------------------------------------------------------


def test_a_modern_server_is_spoken_to_without_a_handshake_and_with_meta_on_every_request(
    serve, tmp_path
):
    server = serve(era="modern")

    code, events = drive(tmp_path, server)

    assert code == 0
    assert sent(events) == ["server/discover", "tools/list"]
    found = decided(events)
    assert (found["era"], found["version"], found["outcome"]) == ("modern", "2026-07-28", "proceed")
    assert found["probe"] == {
        "outcome": "discover_result",
        "code": None,
        "supported": ["2026-07-28"],
    }
    (end,) = of(events, "script_finished")
    assert (end["era"], end["protocol_version"]) == ("modern", "2026-07-28")
    for message in of(events, "message"):
        if message["direction"] == "client_to_server":
            meta = message["payload"]["data"]["params"]["_meta"]
            assert meta["io.modelcontextprotocol/protocolVersion"] == "2026-07-28"
            assert meta["io.modelcontextprotocol/clientInfo"]["name"] == "mcp-kymograph"


def test_modern_requests_carry_the_headers_and_no_session_no_get_and_no_delete(serve, tmp_path):
    server = serve(era="modern")

    drive(tmp_path, server)

    heads = server.behaviour.heads
    assert [(h["method"], h["version"], h["mcp_method"]) for h in heads] == [
        ("POST", "2026-07-28", "server/discover"),
        ("POST", "2026-07-28", "tools/list"),
    ]
    assert {h["session"] for h in heads} == {None}
    recorded = events_of(recording_in(tmp_path / "runs"))
    assert all("mcp-session-id" not in e["headers"] for e in of(recorded, "http_request"))


def test_a_modern_call_names_its_tool_in_mcp_name_and_the_announced_name_is_read(serve, tmp_path):
    server = serve(era="modern", call_result="text")
    script = tmp_path / "script.yaml"
    script.write_text(CALL)

    code, events = drive(tmp_path, server, "--script", str(script), actions=CALLS)

    assert code == 0
    call = [h for h in server.behaviour.heads if h["mcp_method"] == "tools/call"]
    assert [h["mcp_name"] for h in call] == ["tool_0"]
    (called,) = [
        m
        for m in of(events, "message")
        if m["direction"] == "client_to_server" and m["parse"]["method"] == "tools/call"
    ]
    assert called["payload"]["data"]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"]
    (finished,) = of(events, "run_finished")
    assert finished["announced_server"] == "reference-server"  # from server/discover's _meta


@pytest.mark.parametrize("respond", ["json", "stream"])
def test_a_modern_server_whose_response_stream_breaks_is_asked_again_once(serve, tmp_path, respond):
    server = serve(era="modern", respond=respond, break_stream=1)

    code, events = drive(tmp_path, server)

    assert code == 0
    assert [h["mcp_method"] for h in server.behaviour.heads] == [
        "server/discover",
        "tools/list",
        "tools/list",
    ]
    ((again,),) = [[(e["step"], e["page"], e["reason"]) for e in of(events, "step_reissued")]]
    assert again == ("tools/list", 0, "stream_broken")
    ids = [
        m["payload"]["data"]["id"]
        for m in of(events, "message")
        if m["direction"] == "client_to_server"
    ]
    assert len(ids) == len(set(ids)) == 3  # a new request id each time
    assert of(events, "step_unanswered") == []
    assert of(events, "script_finished")[0]["inventory"] == "complete"


def test_a_second_break_is_the_steps_stream_broken(serve, tmp_path, capsys):
    server = serve(era="modern", break_stream=2)

    code, events = drive(tmp_path, server)

    assert code == cli.EXIT_INCOMPLETE
    assert len(of(events, "step_reissued")) == 1  # once, never twice
    ((step, pages, reason),) = [
        (e["step"], e["pages"], e["reason"]) for e in of(events, "step_unanswered")
    ]
    assert (step, pages, reason) == ("tools/list", 0, "stream_broken")
    assert of(events, "script_finished")[0]["inventory"] == "partial"
    assert [h["mcp_method"] for h in server.behaviour.heads].count("tools/list") == 2
    assert "stream_broken" in capsys.readouterr().err


def test_a_call_is_not_sent_twice_when_its_stream_breaks(serve, tmp_path):
    """A listing asks nothing of the world; a call acts, and is not repeated."""
    server = serve(era="modern", call_result="text", break_stream=1, failure_method="tools/call")
    script = tmp_path / "script.yaml"
    script.write_text(CALL)

    code, events = drive(tmp_path, server, "--script", str(script), actions=CALLS)

    assert [h["mcp_method"] for h in server.behaviour.heads].count("tools/call") == 1
    assert of(events, "step_reissued") == []


# -- a server of both eras --------------------------------------------------------------------


def test_a_server_of_both_eras_is_spoken_to_in_the_modern_one(serve, tmp_path):
    server = serve(era="dual", versions=("2025-06-18", "2025-11-25"))

    code, events = drive(tmp_path, server, engaged=True)

    assert code == 0
    assert (decided(events)["era"], decided(events)["version"]) == ("modern", "2026-07-28")
    assert decided(events)["probe"]["supported"] == ["2026-07-28", "2025-06-18", "2025-11-25"]
    assert sent(events) == ["server/discover", "tools/list"]


def test_a_server_of_both_eras_that_does_not_name_ours_is_spoken_to_in_its_legacy_side(
    serve, tmp_path
):
    server = serve(
        era="dual",
        versions=("2025-06-18", "2025-11-25"),
        discover_lists=("2025-06-18", "2025-11-25"),
    )

    code, events = drive(tmp_path, server, engaged=True)

    assert code == 0
    assert sent(events)[:3] == ["server/discover", "initialize", "notifications/initialized"]
    assert (decided(events)["era"], decided(events)["version"]) == ("legacy", "2025-11-25")
    assert decided(events)["probe"]["outcome"] == "discover_result"


# -- every stop ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("behaviour", "reason", "code", "line"),
    [
        (
            {"era": "modern", "refuse": -32021},
            "modern_refused",
            -32021,
            "requires client capabilities this tool does not offer: elicitation (error -32021)",
        ),
        (
            {"era": "modern", "refuse": -32022},
            "no_common_version",
            -32022,
            "rejected protocol version 2026-07-28 although it names it as supported",
        ),
        (
            {"era": "dual", "discover_lists": ("2030-01-01",)},
            "no_common_version",
            None,
            "it names 2030-01-01",
        ),
        (
            {"versions": ("2099-01-01",)},
            "unknown_version",
            None,
            "protocol version 2099-01-01, which this tool does not know",
        ),
    ],
)
def test_a_server_that_requires_what_this_tool_lacks_stops_the_run_with_no_listing(
    serve, tmp_path, capsys, behaviour, reason, code, line
):
    server = serve(**behaviour)

    exit_code, events = drive(tmp_path, server)

    assert exit_code == cli.EXIT_SERVER_FAILED
    found = decided(events)
    assert (found["outcome"], found["reason"]) == ("stop", reason)
    assert code is None or found["refusal"]["code"] == code
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == "protocol_unsupported"
    (end,) = of(events, "script_finished")
    assert end["inventory"] == "none"
    assert "tools/list" not in sent(events)
    assert all(reason == "protocol_unsupported" for _, reason in end["skipped"])
    said = capsys.readouterr().err
    assert "protocol_unsupported: " in said and line in said
    assert "no listing was sent" in said


def test_a_refusing_servers_error_data_is_kept_masked_and_clipped(serve, tmp_path):
    server = serve(era="modern", refuse=-32021)

    _, events = drive(tmp_path, server)

    assert decided(events)["refusal"] == {
        "code": -32021,
        "data": {"requiredCapabilities": {"elicitation": {}}},
    }


def test_a_header_mismatch_on_the_probe_stops_the_run_and_makes_no_header_observation(
    serve, tmp_path
):
    """-32020 is about headers, and over HTTP there were headers: the observation that the code
    came over a transport without any is made over stdio only."""
    server = serve(era="modern", refuse=-32020)

    code, events = drive(tmp_path, server)

    assert code == cli.EXIT_SERVER_FAILED
    assert (decided(events)["reason"], decided(events)["observations"]) == ("modern_refused", [])


# -- what says nothing about the generation --------------------------------------------------


def test_a_probe_that_cannot_be_sent_ends_the_run_with_its_own_reason_and_no_decision(tmp_path):
    out = tmp_path / "runs"
    url = f"http://127.0.0.1:1{http_server.PATH}"

    code = cli.main(["drive", "--http", url, "--out-dir", str(out), "--step-timeout", "5"])

    events = events_of(recording_in(out))
    assert code == cli.EXIT_SERVER_FAILED
    (failed,) = of(events, "server_failed")
    assert failed["reason"] == "http_unreachable"
    assert of(events, "era_decided") == []


def test_a_probe_answered_401_ends_the_run_as_unauthorized(serve, tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_ERA_TOKEN", "an-invented-value")
    server = serve(token_envs=("TEST_ERA_TOKEN",), era="modern")

    code, events = drive(tmp_path, server)

    assert code == cli.EXIT_SERVER_FAILED
    assert of(events, "server_failed")[0]["reason"] == "unauthorized"
    assert of(events, "era_decided") == []


# -- the declared generation -----------------------------------------------------------------


def declared(era, version=None):
    target = {"host": "127.0.0.1", "era": era}
    if version:
        target["version"] = version
    return [target]


def test_a_declared_generation_that_is_the_one_found_is_recorded_as_agreeing(serve, tmp_path):
    server = serve(era="modern")

    _, events = drive(tmp_path, server, targets=declared("modern", "2026-07-28"))

    found = decided(events)
    assert found["declared"] == {"era": "modern", "version": "2026-07-28"}
    assert found["differs"] is False


def test_a_declared_generation_that_is_not_found_is_an_observation_and_no_stop(
    serve, tmp_path, capsys
):
    server = serve()  # legacy

    code, events = drive(tmp_path, server, targets=declared("modern"))

    assert code == 0  # the run is not stopped
    found = decided(events)
    assert found["declared"] == {"era": "modern", "version": None}
    assert (found["era"], found["differs"]) == ("legacy", True)
    assert "declares modern for this endpoint; the server speaks legacy 2025-06-18" in (
        capsys.readouterr().err
    )


def test_a_declared_version_that_is_not_the_one_spoken_differs_too(serve, tmp_path):
    server = serve(versions=("2025-06-18",))

    _, events = drive(tmp_path, server, targets=declared("legacy", "2025-11-25"))

    assert (decided(events)["era"], decided(events)["differs"]) == ("legacy", True)


def test_a_generation_declared_for_another_target_is_not_compared(serve, tmp_path):
    server = serve()

    _, events = drive(
        tmp_path,
        server,
        targets=[
            {"host": "127.0.0.1", "ports": [1], "era": "modern"},
            {"host": "127.0.0.1"},
        ],
    )

    assert decided(events)["declared"] is None


# -- over stdio ------------------------------------------------------------------------------


def test_a_modern_stdio_server_is_modern_under_an_engagement(tmp_path):
    code, events = drive_stdio(tmp_path, "modern_server.py", engaged=True)

    assert code == 0
    assert sent(events) == ["server/discover", "tools/list"]
    assert (decided(events)["era"], decided(events)["version"]) == ("modern", "2026-07-28")
    assert of(events, "script_finished")[0]["era"] == "modern"


def test_a_modern_stdio_server_is_as_it_was_without_an_engagement(tmp_path):
    """The pinned behaviour: stdio is opened by initialize alone, asking for 2025-06-18, and a
    server of the modern era only has no answer to it."""
    code, events = drive_stdio(tmp_path, "modern_server.py")

    assert code == cli.EXIT_SERVER_FAILED
    assert sent(events) == ["initialize"] and asked_version(events) == "2025-06-18"
    assert of(events, "era_decided") == []


@pytest.mark.parametrize(
    ("versions", "found"),
    [("2025-06-18,2025-11-25", "2025-11-25"), ("2025-06-18", "2025-06-18")],
)
def test_a_legacy_stdio_server_is_asked_for_2025_11_25_under_an_engagement(
    tmp_path, versions, found
):
    code, events = drive_stdio(tmp_path, "legacy_server.py", "--versions", versions, engaged=True)

    assert code == 0
    assert asked_version(events) == "2025-11-25"
    assert (decided(events)["era"], decided(events)["version"]) == ("legacy", found)
    assert of(events, "script_finished")[0]["protocol_version"] == found


def test_a_legacy_stdio_server_is_asked_for_2025_06_18_without_one_and_not_probed(tmp_path):
    code, events = drive_stdio(tmp_path, "legacy_server.py", "--versions", "2025-06-18,2025-11-25")

    assert code == 0
    assert sent(events)[0] == "initialize" and asked_version(events) == "2025-06-18"
    assert of(events, "era_decided") == []
    (end,) = of(events, "script_finished")
    assert (end["era"], end["protocol_version"]) == ("legacy", "2025-06-18")


def test_a_modern_stdio_server_that_refuses_the_probe_stops_under_an_engagement(tmp_path, capsys):
    code, events = drive_stdio(tmp_path, "modern_server.py", "--refuse", "-32021", engaged=True)

    assert code == cli.EXIT_SERVER_FAILED
    assert (decided(events)["reason"], of(events, "server_failed")[0]["reason"]) == (
        "modern_refused",
        "protocol_unsupported",
    )
    assert "requires client capabilities this tool does not offer: elicitation" in (
        capsys.readouterr().err
    )


# -- the announced name in the modern era ------------------------------------------------------


def discover_answer(name="weather-server") -> dict:
    meta = {eras.META_SERVER_INFO: {"name": name, "version": "1"}}
    result = {"supportedVersions": ["2026-07-28"], "capabilities": {}, "_meta": meta}
    return {"jsonrpc": "2.0", "id": 0, "result": result}


def test_the_name_the_modern_server_announces_in_the_probe_answer_is_read_and_never_keyed_on():
    inspector = Inspector(server="corpus-entry")

    look = look_at(inspector, "server/discover", discover_answer())

    assert (look.answered_initialize, look.announced) == (True, "weather-server")
    assert inspector.announced_server == "weather-server"


@pytest.mark.parametrize(
    "document",
    [
        {"jsonrpc": "2.0", "id": 0, "result": {"supportedVersions": [], "_meta": {}}},
        {"jsonrpc": "2.0", "id": 0, "result": {"_meta": {eras.META_SERVER_INFO: "weather"}}},
    ],
)
def test_a_probe_answer_that_announces_no_name_leaves_none(document):
    inspector = Inspector()

    look = look_at(inspector, "server/discover", document)

    assert (look.answered_initialize, inspector.announced_server) == (True, None)


def test_an_error_answer_to_the_probe_announces_nothing():
    """A legacy server's -32601 or a modern one's -32022 is no announcement, not even of no name:
    the name then comes from ``initialize``, or the run stopped before one."""
    inspector = Inspector(server="corpus-entry")
    error = {"jsonrpc": "2.0", "id": 0, "error": {"code": -32601, "message": "no"}}

    look = look_at(inspector, "server/discover", error)

    assert (look.answered_initialize, look.announced, inspector.announced_server) == (
        False,
        None,
        None,
    )


def test_the_name_in_an_answer_to_another_method_is_not_the_servers():
    inspector = Inspector()

    look = look_at(inspector, "tools/list", discover_answer("impostor"))

    assert (look.answered_initialize, inspector.announced_server) == (False, None)


# -- the declared name and the probe's error answer --------------------------------------------


def named_manifest(tmp_path, name, **entry):
    """A manifest with the one entry: the name a corpus run declares for the server."""
    path = tmp_path / "corpus" / "manifest.json"
    path.parent.mkdir(exist_ok=True)
    scenario = os.path.relpath(FIXTURES / "scenarios" / "all-signals.yaml", path.parent)
    entry = {"name": name, "provenance": "poison", "scenarios": [scenario], **entry}
    path.write_text(json.dumps({"version": 1, "entries": [entry]}))
    return path


def http_entry(tmp_path, server, name):
    return named_manifest(
        tmp_path,
        name,
        source={"endpoint": url_of(server)},
        launch={"transport": "streamable-http"},
    )


def drive_declared(tmp_path, manifest, name):
    """A corpus run under an engagement: the server's name is declared by the entry."""
    out = tmp_path / "runs"
    engagement = write_engagement(tmp_path / "engagement")
    argv = ["drive", "--manifest", str(manifest), "--entry", name]
    argv += ["--engagement", str(engagement), "--out-dir", str(out), "--step-timeout", "5"]
    code = cli.main(argv)
    return code, events_of(recording_in(out))


def test_a_legacy_server_that_errors_on_the_probe_is_no_name_mismatch_over_http(serve, tmp_path):
    name = http_server.VARIANTS["reference"][0]
    server = serve()

    code, events = drive_declared(tmp_path, http_entry(tmp_path, server, name), name)

    assert code == 0
    assert decided(events)["probe"]["outcome"] == "other_error"
    assert of(events, "server_name_mismatch") == []
    assert of(events, "run_finished")[0]["announced_server"] == name


def test_the_declared_name_is_still_compared_with_the_one_initialize_announces(serve, tmp_path):
    """The other side of the test above: a real difference is still found, with the name
    ``initialize`` announced and not None."""
    server = serve()

    _, events = drive_declared(tmp_path, http_entry(tmp_path, server, "impostor"), "impostor")

    (mismatch,) = of(events, "server_name_mismatch")
    assert (mismatch["declared"], mismatch["announced"]) == ("impostor", "reference-server")


def test_a_legacy_stdio_server_that_errors_on_the_probe_is_no_name_mismatch(tmp_path):
    script = ERA_SERVERS / "legacy_server.py"
    manifest = named_manifest(
        tmp_path,
        "legacy",
        source={"paths": [os.path.relpath(script, tmp_path / "corpus")]},
        launch={"transport": "stdio", "command": [sys.executable, str(script)]},
    )

    code, events = drive_declared(tmp_path, manifest, "legacy")

    assert code == 0
    assert decided(events)["probe"]["outcome"] == "other_error"
    assert of(events, "server_name_mismatch") == []


@pytest.mark.parametrize("refuse", [-32021, -32022, -32020])
def test_a_stop_after_a_modern_error_answer_is_no_name_mismatch(serve, tmp_path, refuse):
    name = http_server.VARIANTS["reference"][0]
    server = serve(era="modern", refuse=refuse)

    code, events = drive_declared(tmp_path, http_entry(tmp_path, server, name), name)

    assert code == cli.EXIT_SERVER_FAILED
    assert of(events, "server_failed")[0]["reason"] == "protocol_unsupported"
    assert of(events, "server_name_mismatch") == []


# -- the words of a stop -----------------------------------------------------------------------


def test_a_server_that_rejects_the_version_it_lists_is_said_to_do_so(serve, tmp_path, capsys):
    server = serve(era="modern", refuse=-32022)

    _, events = drive(tmp_path, server)

    (failed,) = of(events, "server_failed")
    assert (
        "rejected protocol version 2026-07-28 although it names it as supported"
        in (failed["detail"])
    )
    said = capsys.readouterr().err
    assert "the server rejected protocol version 2026-07-28 although it names it" in said
    assert "speaks no protocol version this tool does" not in said


def test_a_server_that_names_no_version_this_tool_speaks_is_said_to_do_so(serve, tmp_path, capsys):
    server = serve(era="dual", discover_lists=("2030-01-01",))

    _, events = drive(tmp_path, server)

    (failed,) = of(events, "server_failed")
    assert failed["detail"] == (
        "the server names no protocol version this tool speaks (it names: 2030-01-01)"
    )
    said = capsys.readouterr().err
    assert "the server speaks no protocol version this tool does: it names 2030-01-01" in said
    assert "although it names it as supported" not in said


# -- the probe that a stdio server closes on ---------------------------------------------------


def test_a_stdio_server_that_closes_on_the_probe_is_said_to_have_closed_on_it(tmp_path):
    code, events = drive_stdio(tmp_path, "legacy_server.py", "--unknown", "exit", engaged=True)

    assert code == cli.EXIT_SERVER_FAILED
    assert decided(events)["reason"] == "closed_on_probe"
    (failed,) = of(events, "server_failed")
    assert failed["detail"] == "the server's side closed before server/discover was answered"
