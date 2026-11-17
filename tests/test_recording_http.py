"""One recording format for stdio and Streamable HTTP (schema 4).

No network: the recorder is given what a proxy would have read off the wire, and the file it
writes is read back. The property under test is the one the recorder exists for — a secret that
goes in does not come out in the clear — now for the places only HTTP has: heads, targets,
the endpoint, stream event ids.
"""

import json

import pytest

from mcp_kymograph import events, verdict
from mcp_kymograph.events import SCHEMA_VERSION, Direction
from mcp_kymograph.masking import Masker
from mcp_kymograph.recorder import Recorder

LIMITS = {"max_message_bytes": 1048576}
CLOSED = {"server_output_bytes": 100, "client_input_bytes": 100, "server_exited_first": False}

# Distinctive values, not real credentials: a search over the raw recording must find none. The
# secret is put together when the test runs, so that no scanner finds it written out here.
SECRET = "".join(("geheim-", "Zx9Q", "w7Lm2", "Vb8K", "d4Rt6"))


class Numbered:
    """Hands out envelopes the way the sink does."""

    def __init__(self, recorder: Recorder) -> None:
        self.recorder = recorder
        self.seq = 0

    def __call__(self, name: str, /, **kwargs) -> None:
        self.seq += 1
        getattr(self.recorder, name)(self.seq, self.seq * 1000, **kwargs)


@pytest.fixture
def path(tmp_path):
    return tmp_path / "events.jsonl"


@pytest.fixture
def emit(path):
    with Recorder.open(
        path, run_id="httprun", masker=Masker(), verbatim_paths=[("server", 8080, "/mcp")]
    ) as recorder:
        yield Numbered(recorder)


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def http_run(emit, *, endpoint="http://server:8080/mcp", request_headers=(), response_headers=()):
    """A whole driven HTTP run: one exchange that answers, in one stream."""
    emit(
        "run_started", argv=[], limits=LIMITS, mode="driver", script="discovery",
        transport=events.TRANSPORT_HTTP, endpoint=endpoint,
    )  # fmt: skip
    emit(
        "http_request", exchange=1, connection=1, method="POST", target="/mcp",
        headers=[("Content-Type", "application/json"), *request_headers], session=None,
    )  # fmt: skip
    emit(
        "message", direction=Direction.CLIENT_TO_SERVER,
        raw=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        transport=events.TRANSPORT_HTTP, exchange=1,
    )  # fmt: skip
    emit(
        "http_response", exchange=1, status=200, reason="OK",
        headers=[("Content-Type", "text/event-stream"), *response_headers],
        content_type="text/event-stream", framing="sse", session=1,
    )  # fmt: skip
    emit(
        "message", direction=Direction.SERVER_TO_CLIENT,
        raw=b'{"jsonrpc":"2.0","id":1,"result":{}}',
        transport=events.TRANSPORT_HTTP, responded_method="ping", exchange=1, stream=1,
        event_id="evt-7",
    )  # fmt: skip
    emit(
        "http_end", exchange=1, ended="complete", request_body_bytes=40,
        response_body_bytes=36, head_bytes=200, events=1, comments=0,
    )  # fmt: skip
    emit("script_finished", inventory="complete")
    emit("run_finished", reason="client_eof", duration_ns=5, http={"exchanges": 1}, **CLOSED)


def test_an_http_run_is_one_file_of_schema_4_that_the_verdict_reads(path, emit):
    """Transport, endpoint, three HTTP events, HTTP fields in the messages, counts at the end."""
    http_run(emit)
    lines = read_events(path)
    assert [line["type"] for line in lines] == [
        "run_started", "http_request", "message", "http_response", "message", "http_end",
        "script_finished", "run_finished",
    ]  # fmt: skip
    assert all(line["v"] == 5 for line in lines)
    started = lines[0]
    assert started["transport"] == "streamable-http"
    assert started["schema_version"] == 5
    assert started["endpoint"] == {
        "scheme": "http", "host": "server", "port": 8080, "path": "/mcp", "query": {},
        "userinfo_dropped": False,
    }  # fmt: skip
    request, response = lines[2], lines[4]
    assert (request["exchange"], request["stream"], request["event_id"]) == (1, None, None)
    assert (response["exchange"], response["stream"]) == (1, 1)
    assert response["event_id"] and response["event_id"] != "evt-7"
    assert lines[1]["session"] is None and lines[3]["session"] == 1
    assert lines[5]["ended"] == "complete" and lines[5]["events"] == 1
    assert lines[-1]["http"] == {"exchanges": 1}
    judged = verdict.read(path)
    assert "schema" not in judged.causes, judged.problems


def test_no_secret_is_written_in_the_clear_anywhere(path, emit):
    """Credentials in heads, query, userinfo, path and a Set-Cookie leave nothing in the file."""
    url = f"http://user:{SECRET}-pw@server:8080/mcp/Bearer {SECRET}-path?access_token={SECRET}-q"
    emit(
        "run_started", argv=[], limits=LIMITS, transport=events.TRANSPORT_HTTP, endpoint=url
    )  # fmt: skip
    emit(
        "http_request", exchange=1, connection=1, method="POST",
        target=f"/mcp/Bearer {SECRET}-tpath?access_token={SECRET}-tq#access_token={SECRET}-frag",
        headers=[
            ("Authorization", f"Bearer {SECRET}-auth"),
            ("Cookie", f"sid={SECRET}-cookie"),
            ("Mcp-Session-Id", f"{SECRET}-session"),
        ],
        session=1,
    )  # fmt: skip
    emit(
        "http_response", exchange=1, status=200, reason="OK",
        headers=[
            ("Set-Cookie", f"sid={SECRET}-setcookie; HttpOnly"),
            ("Mcp-Session-Id", f"{SECRET}-session2"),
        ],
        content_type="application/json", framing="json", session=1,
    )  # fmt: skip
    emit("run_finished", reason="client_eof", duration_ns=5, **CLOSED)
    raw = path.read_text()
    assert SECRET not in raw
    started = json.loads(raw.splitlines()[0])
    assert started["endpoint"]["userinfo_dropped"] is True
    assert started["endpoint"]["host"] == "server"
    assert "user:" not in raw and "user@" not in raw
    assert "Zx9Qw7" not in raw  # not even a piece of it


def test_a_session_is_taken_as_an_ordinal_only(emit):
    """Handing over a session id instead of its ordinal is refused, not written."""
    with pytest.raises(ValueError):
        emit(
            "http_request", exchange=1, connection=1, method="POST", target="/mcp",
            headers=[], session=f"{SECRET}-session",
        )  # fmt: skip


def test_www_authenticate_stays_readable_as_parsed(path, emit):
    """The challenge is kept as realm, resource_metadata and error, not blanked whole."""
    challenge = (
        'Bearer realm="x", resource_metadata="https://a.example/meta", error="invalid_token"'
    )
    http_run(emit, response_headers=[("WWW-Authenticate", challenge)])
    shown = json.dumps(read_events(path)[3]["headers"]["www-authenticate"])
    for expected in ("realm", "x", "resource_metadata", "https://a.example", "error",
                     "invalid_token"):  # fmt: skip
        assert expected in shown, shown
    # The URL's path is the endpoint rule's: withheld unless the file lists it.
    assert "/meta" not in shown, shown


def test_server_redactions_count_response_heads_and_not_request_heads(path, emit):
    """A credential the client sends is ordinary; one in the server's head is counted."""
    http_run(emit, request_headers=[("Authorization", f"Bearer {SECRET}"), ("Cookie", "a=b")])
    assert read_events(path)[-1]["server_redactions"] == 0
    other = path.with_name("second.jsonl")
    with Recorder.open(other, run_id="second", masker=Masker()) as recorder:
        second = Numbered(recorder)
        http_run(second, response_headers=[("Set-Cookie", f"sid={SECRET}"), ("Cookie", "x=y")])
    # Set-Cookie and Cookie in the response head: one hit each.
    assert read_events(other)[-1]["server_redactions"] == 2


def test_the_same_event_id_gives_the_same_pseudonym_within_a_run(path, emit):
    """Equal ids correlate, different ids do not, the id is not in the file, empty stays empty."""
    for event_id in ("evt-alpha-1", "evt-alpha-1", "evt-beta-2", ""):
        emit(
            "message", direction=Direction.SERVER_TO_CLIENT, raw=b"{}",
            transport=events.TRANSPORT_HTTP, exchange=1, stream=1, event_id=event_id,
        )  # fmt: skip
    ids = [line["event_id"] for line in read_events(path)]
    assert ids[0] == ids[1] != ids[2]
    assert ids[0] not in ("", "evt-alpha-1") and ids[3] == ""
    raw = path.read_text()
    assert "evt-alpha-1" not in raw and "evt-beta-2" not in raw


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        (
            "http_response",
            {"exchange": 1, "status": 200, "reason": "OK", "headers": [], "content_type": None,
             "framing": "chunked"},
        ),
        (
            "http_end",
            {"exchange": 1, "ended": "vanished", "request_body_bytes": 0,
             "response_body_bytes": 0, "head_bytes": 0},
        ),
        ("run_started", {"argv": [], "limits": LIMITS, "transport": "websocket"}),
        ("run_started", {"argv": [], "limits": LIMITS, "endpoint": "http://server/mcp"}),
        (
            "run_started",
            {"argv": [], "limits": LIMITS, "transport": "stdio", "endpoint": "http://s/mcp"},
        ),
    ],
)  # fmt: skip
def test_a_word_outside_the_closed_sets_is_refused(emit, method, kwargs):
    """Framing, ending and transport are ours: a wrong one is the caller's bug, not traffic."""
    with pytest.raises(ValueError):
        emit(method, **kwargs)


def test_a_stdio_run_has_the_same_events_with_the_http_fields_empty(path, emit):
    """Nothing is added to a stdio recording but the fields, and they are null."""
    emit("run_started", argv=["srv"], limits=LIMITS)
    emit("message", direction=Direction.CLIENT_TO_SERVER, raw=b'{"id":1,"method":"ping"}')
    emit("server_exited", exit_code=0)
    emit("run_finished", reason="client_eof", duration_ns=5, **CLOSED)
    lines = read_events(path)
    assert [line["type"] for line in lines] == [
        "run_started", "message", "server_exited", "run_finished"
    ]  # fmt: skip
    assert (lines[0]["transport"], lines[0]["endpoint"]) == ("stdio", None)
    assert lines[1]["transport"] == "stdio"
    assert (lines[1]["exchange"], lines[1]["stream"], lines[1]["event_id"]) == (None, None, None)
    assert lines[3]["http"] is None
    assert all(line["v"] == 5 for line in lines)


def test_a_recording_of_schema_4_is_refused_and_one_of_schema_5_is_read(tmp_path):
    """The verdict reads exactly the schema of the constant: 4 is a cause, 5 is not."""
    assert SCHEMA_VERSION == 5

    def write(number):
        lines = [
            {"v": number, "type": "run_started", "mode": "driver", "isolation": "host",
             "schema_version": number},
            {"v": number, "type": "script_finished", "inventory": "complete"},
            {"v": number, "type": "run_finished", "findings_by_statement": {}, **CLOSED},
        ]  # fmt: skip
        target = tmp_path / f"schema-{number}.jsonl"
        target.write_text("".join(json.dumps(line) + "\n" for line in lines))
        return target

    refused = verdict.read(write(4))
    assert (refused.state, refused.causes) == (verdict.INCOMPLETE, ["schema"])
    accepted = verdict.read(write(5))
    assert "schema" not in accepted.causes and accepted.state == verdict.COMPLETE


# -- user information, percent-encoded paths, lengths -----------------------------------------

SECRET2 = "".join(("geheim-", "Zx9Q", "w7Lm2", "Vb8K", "d4Rt6"))


def _one_request(tmp_path, target, verbatim=()):
    """One request head, recorded; ``verbatim`` are the paths the run may write as they are, on
    the host and port of its endpoint, which a request in origin form is made to."""
    path = tmp_path / "events.jsonl"
    paths = [("server", 8080, p) for p in verbatim]
    with Recorder.open(path, run_id="r", masker=Masker(), verbatim_paths=paths) as rec:
        rec.run_started(
            1, 1, argv=[], limits={}, transport="streamable-http", endpoint="http://server:8080/mcp"
        )
        rec.http_request(2, 2, exchange=1, connection=1, method="POST", target=target, headers=[])
    return path.read_text(), json.loads(path.read_text().splitlines()[-1])


@pytest.mark.parametrize(
    "target",
    [
        f"http://alice:{SECRET2}@server/mcp?x=1",
        f"HTTP://alice:{SECRET2}@server:8080/mcp",
        f"alice:{SECRET2}@server:8080",
        f"alice:{SECRET2}@server:8080/mcp",
    ],
)
def test_user_information_in_any_form_of_target_is_dropped(tmp_path, target):
    """Absolute form (RFC 9112 3.2.2) and anything else with an ``@`` in its first segment: the
    user and password never reach the file, and the event says something was dropped."""
    text, event = _one_request(tmp_path, target)
    assert SECRET2 not in text and "alice" not in text
    assert event["target"]["userinfo_dropped"] is True


@pytest.mark.parametrize(
    "target",
    [
        f"/mcp/Bearer%20{SECRET2}",
        f"/mcp/Bearer%2520{SECRET2}",
        f"/mcp/Bearer%252520{SECRET2}",
        f"/mcp/Bearer%25252520{SECRET2}",
    ],
)
def test_a_percent_encoded_secret_in_the_path_is_blanked(tmp_path, target):
    """Decoded as often as mask_query decodes, and blanked if any decoding shows a credential or
    it still decodes after the last; kept as sent otherwise."""
    text, event = _one_request(tmp_path, target, verbatim=[target])
    assert SECRET2 not in text
    assert event["target"]["path"] == "***REDACTED***"


@pytest.mark.parametrize("target", ["/mcp/a%20b", "/mcp/a%2520b"])
def test_a_path_with_nothing_to_mask_is_kept_as_sent(tmp_path, target):
    """Decoding is only looked through, never kept: a harmless path stays as it came, also when
    it is encoded twice."""
    _, event = _one_request(tmp_path, target, verbatim=[target])
    assert event["target"]["path"] == target
    assert event["target"]["userinfo_dropped"] is False


@pytest.mark.parametrize(
    "target",
    [
        f"//alice:{SECRET2}@server/mcp",
        f"/proxy/http://alice:{SECRET2}@server/mcp",
        f"http://alice:pa/{SECRET2}@server/mcp",
        f"http:///alice:{SECRET2}@server/mcp",
        f"http:/alice:{SECRET2}@server/mcp",
        f"/proxy/http://alice:{SECRET2}%40server/mcp",
        f"//alice:{SECRET2}%2540server/mcp",
    ],
)
def test_no_at_sign_is_kept_in_a_recorded_path(tmp_path, target):
    """Where parsers disagree about where the authority ends, the whole path is blanked."""
    text, event = _one_request(tmp_path, target)
    assert SECRET2 not in text and "alice" not in text
    assert event["target"]["path"] == "***REDACTED***"
    assert event["target"]["userinfo_dropped"] is True


@pytest.mark.parametrize(
    "endpoint",
    [
        f"alice:{SECRET2}@server:8080/mcp",
        f"http:alice:{SECRET2}@server/mcp",
        "server:8080/mcp",
        "ftp://server/mcp",
    ],
)
def test_an_endpoint_without_scheme_or_host_is_refused(tmp_path, endpoint):
    """urlsplit would read user and password as a path there: refused, not recorded."""
    with (
        Recorder.open(tmp_path / "e.jsonl", run_id="r", masker=Masker()) as rec,
        pytest.raises(ValueError),
    ):
        rec.run_started(1, 1, argv=[], limits={}, transport="streamable-http", endpoint=endpoint)
    assert SECRET2 not in (tmp_path / "e.jsonl").read_text()


def test_an_endpoint_path_with_a_percent_encoded_secret_is_blanked(tmp_path):
    """The endpoint's path goes through the same decoding as a request target's."""
    path = tmp_path / "events.jsonl"
    with Recorder.open(
        path,
        run_id="r",
        masker=Masker(),
        verbatim_paths=[("server", 8080, f"/mcp/Bearer%20{SECRET2}")],
    ) as rec:
        rec.run_started(1, 1, argv=[], limits={}, transport="streamable-http",
                        endpoint=f"http://server:8080/mcp/Bearer%20{SECRET2}")  # fmt: skip
    assert SECRET2 not in path.read_text()


def test_path_host_and_query_are_capped(tmp_path):
    """A long path, many query fields and long values stay bounded in the event."""
    query = "&".join(f"f{i}={'v' * 2000}" for i in range(100))
    long = "/" + "p" * 10_000
    _, event = _one_request(tmp_path, long + "?" + query, verbatim=[long])
    assert len(event["target"]["path"]) == 2048
    fields = event["target"]["query"]
    assert len(fields) == 65 and fields["…"] == 36
    assert all(len(v) <= 512 for k, v in fields.items() if k != "…")


def test_a_password_with_a_slash_in_the_endpoint_is_not_kept(tmp_path):
    """urlsplit ends the authority at the first ``/`` and reads the rest of the password as a
    port: refused before anything is written."""
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="r", masker=Masker()) as rec, pytest.raises(ValueError):
        rec.run_started(
            1,
            1,
            argv=[],
            limits={},
            transport="streamable-http",
            endpoint=f"http://alice:pa/{SECRET2}@server:8080/mcp",
        )
    assert SECRET2 not in path.read_text()


@pytest.mark.parametrize(
    "endpoint",
    [
        f"http://alice:8080/{SECRET2}@server/mcp",
        f"http://alice:/{SECRET2}@server/mcp",
        f"http://server/mcp/alice:{SECRET2}%40x",
        f"http://server:8080/mcp/alice:{SECRET2}@x",
    ],
)
def test_an_endpoint_whose_path_holds_an_at_sign_is_refused(tmp_path, endpoint):
    """Where the authority ends is not clear there: refused, and neither user nor password is
    written, not as a host or a port either."""
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="r", masker=Masker()) as rec, pytest.raises(ValueError):
        rec.run_started(1, 1, argv=[], limits={}, transport="streamable-http", endpoint=endpoint)
    assert SECRET2 not in path.read_text() and "alice" not in path.read_text()


def test_an_at_sign_in_the_query_of_an_endpoint_is_no_user_information(tmp_path):
    """An address in a query value is not where user information stands: kept, and masked as
    a query is."""
    path = tmp_path / "events.jsonl"
    with Recorder.open(
        path, run_id="r", masker=Masker(), verbatim_paths=[("server", 8080, "/mcp")]
    ) as rec:
        rec.run_started(
            1,
            1,
            argv=[],
            limits={},
            transport="streamable-http",
            endpoint="http://server:8080/mcp?contact=ops@example.org",
        )
    endpoint = json.loads(path.read_text())["endpoint"]
    assert endpoint["path"] == "/mcp" and endpoint["userinfo_dropped"] is False


def test_a_path_that_still_decodes_after_the_last_round_is_blanked(tmp_path):
    """An @ encoded once more than the rounds the masking decodes: not looked through, and not
    trusted either, so the path is blanked as one that holds an @."""
    target = f"//alice:{SECRET2}%2525252540server/mcp"
    text, event = _one_request(tmp_path, target)
    assert SECRET2 not in text
    assert event["target"]["path"] == "***REDACTED***"
    assert event["target"]["userinfo_dropped"] is True
