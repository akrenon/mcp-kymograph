"""Token observations (docs/engagements.md, "Token observations"): an identity of a file of the
second version marked ``observation`` is a run that records how the server answered a token that
is foreign, expired or absent. Against the HTTP fixture with a server that judges the token
(``token_server``), through ``cli.main``. A 401 or 403 is the result there, not a failure; no
byte of a token is in any artifact.
"""

from __future__ import annotations

import collections
import contextlib
import dataclasses
import io
import json
import os
import re
import secrets
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

from mcp_kymograph import (
    cli,
    driver,
    engagement,
    events,
    http_client,
    masking,
    recorder,
    verdict,
)
from mcp_kymograph.http_client import REJECTION_BODY_SECONDS
from mcp_kymograph.web.views import Sources
from test_cli_engagement import events_of, run_directories
from test_identities import token_file_engagement
from test_personal_data import SALT_ENV, second_file
from test_token_artifacts import every_view
from test_token_claims import made_up_jwt, pieces

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_limits  # noqa: E402
import http_server  # noqa: E402
import rejecting_server  # noqa: E402
import token_server  # noqa: E402
from token_server import Policy  # noqa: E402

TOKEN_ENV = "TEST_TOKEN_OBSERVED"  # noqa: S105 - the name of a variable
SERVED = "api://" + secrets.token_hex(4)
ELSEWHERE = "api://" + secrets.token_hex(4)


def long_ago() -> int:
    return int((datetime.now(timezone.utc) - timedelta(hours=2)).timestamp())


def in_an_hour() -> int:
    return int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())


def identity(kind: str | None) -> dict:
    """The one identity of the file: ``observer``, marked ``kind``. ``no_token`` sends none."""
    named = {"name": "observer", "role": "observation", "observation": kind}
    named = {key: value for key, value in named.items() if value is not None}
    return {**named, "token": "none"} if kind == "no_token" else {**named, "token_env": TOKEN_ENV}


SCRIPT = {
    "version": 1,
    "name": "one-call",
    "steps": ["initialize", {"list": "tools/list"}, {"call": {"tool": "tool_0"}}],
}


class Run:
    """One ``drive --script`` as ``observer``: its exit code, the recording and what it wrote."""

    def __init__(self, code: int, directory: Path, out: str, err: str) -> None:
        self.code, self.directory, self.out, self.err = code, directory, out, err
        (self.run,) = run_directories(directory / "runs")
        self.path = self.run / "events.jsonl"
        self.events = events_of(self.path)

    def of(self, kind: str) -> list[dict]:
        return [event for event in self.events if event["type"] == kind]

    @property
    def started(self) -> dict:
        return self.of("run_started")[0]

    @property
    def exchanges(self) -> list[dict]:
        (observed,) = self.of("token_observation")
        return observed["exchanges"]

    def roles(self) -> list[str]:
        return [x["role"] for x in self.exchanges]

    def in_role(self, role: str) -> list[dict]:
        return [x for x in self.exchanges if x["role"] == role]

    @property
    def skipped(self) -> list[tuple[str, str]]:
        return [(e["step"], e["reason"]) for e in self.of("step_skipped")]


@pytest.fixture
def serve():
    started = []

    def start(policy: Policy, **behaviour):
        behaviour.setdefault("call_result", "text")
        server = token_server.serve(policy, **behaviour)
        started.append(server)
        return server

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.fixture
def awkward():
    """``awkward(policy, rejection=..., mirror=...)``: a server of ``rejecting_server``."""
    started = []

    def start(policy: Policy, **behaviour):
        behaviour.setdefault("call_result", "text")
        server = rejecting_server.serve(policy, **behaviour)
        started.append(server)
        return server

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.fixture
def drive(tmp_path, monkeypatch):
    """``drive(server, kind, token=...)``: a run as ``observer`` marked ``kind``, with ``token`` in
    the variable the identity names (none for ``no_token``)."""
    monkeypatch.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
    count = 0

    def run(
        server,
        kind: str | None,
        token: str | None = None,
        *more: str,
        probe: bool = False,
        known: tuple[str, ...] = (),
    ) -> Run:
        nonlocal count
        count += 1
        directory = tmp_path / f"run{count}"
        if token is not None:
            monkeypatch.setenv(TOKEN_ENV, token)
        held = second_file(
            directory / "engagement",
            identities=[identity(kind)],
            actions={"list": True, "call": True, **({"probes": ["echo"]} if probe else {})},
            tools=[{"name": "tool_0", "writes": False}],
            known_values=list(known),
        )
        script = directory / "script.json"
        script.write_text(json.dumps(SCRIPT))
        what = (
            ["--probe", "echo", "--probe-option", "tool=tool_0"]
            if probe
            else ["--script", str(script)]
        )
        out, err = io.StringIO(), io.StringIO()
        url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(
                [
                    "drive", "--engagement", str(held), "--out-dir", str(directory / "runs"),
                    *what, "--http", url, "--identity", "observer", *more,
                ]
            )  # fmt: skip
        return Run(code, directory, out.getvalue(), err.getvalue())

    return run


def jwt(**claims) -> str:
    return made_up_jwt(claims)[0]


# -- one accepting and one rejecting server for each kind ------------------------------------------

KINDS = {
    "foreign_audience": (lambda: jwt(aud=ELSEWHERE, exp=in_an_hour()), Policy(audience=SERVED)),
    "expired": (lambda: jwt(aud=SERVED, exp=long_ago()), Policy(check_exp=True)),
    "no_token": (lambda: None, Policy()),
}

ERAS = ["legacy", "modern"]


@pytest.mark.parametrize("era", ERAS)
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_server_that_accepts_has_every_exchange_accepted_and_the_run_is_complete(
    kind, era, serve, drive
):
    token, _ = KINDS[kind]
    accepting = Policy(anonymous_ok=True)
    found = drive(serve(accepting, era=era), kind, token())

    assert found.code == 0
    assert verdict.read(found.path).state == verdict.COMPLETE
    assert found.started["auth"]["observation"] == kind
    (observed,) = found.of("token_observation")
    assert observed["kind"] == kind
    # Counted by role. In the modern era ``server/discover`` is the opening; in the legacy era it
    # is the era probe, and ``initialize`` is the opening.
    expected = {"opening": 1, "list": 1, "call": 1}
    if era == "legacy":
        expected["era_probe"] = 1
    assert collections.Counter(found.roles()) == expected
    assert all(x["accepted"] is True for x in found.exchanges if x["role"] != "era_probe")
    assert [x["http_status"] for x in found.in_role("list") + found.in_role("call")] == [200, 200]
    # The era probe of a legacy server is answered 400 for the method it does not know: an
    # answer, neither accepted nor rejected, which says nothing of the token.
    for probe in found.in_role("era_probe"):
        assert (probe["accepted"], probe["http_status"]) == (None, 400)
    assert all(reason != "observation_rejected" for _, reason in found.skipped)
    assert found.of("step_called") and found.of("server_failed") == []


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_server_that_rejects_ends_the_run_there_and_the_run_is_complete(
    kind, status, serve, drive
):
    token, policy = KINDS[kind]
    found = drive(serve(policy, deny_status=status), kind, token())

    assert found.code == 0, found.err
    assert verdict.read(found.path).state == verdict.COMPLETE
    assert found.of("server_failed") == [] and found.of("step_unanswered") == []
    assert all(e.get("reason") != "unauthorized" for e in found.events)
    (rejected,) = [x for x in found.exchanges if not x["accepted"]]
    assert found.exchanges[-1] == rejected
    # The fixture sends a JSON-RPC error with its code in the body of the refusal.
    assert rejected["http_status"] == status and rejected["rpc_code"] == -32001
    # The server refused the first request there is, the one that opens the conversation.
    assert found.roles() == ["opening"]
    # The steps after it say why they were not sent; they are not left out.
    assert [step for step, _ in found.skipped] == ["tools/list", "tools/call"]
    assert {reason for _, reason in found.skipped} == {"observation_rejected"}
    assert f"rejected\tstatus {status}\tcode -32001" in found.out
    assert found.of("script_finished")[0]["inventory"] == "none"


@pytest.mark.parametrize("era", ERAS)
def test_a_server_that_refuses_only_the_call_has_it_rejected_and_the_rest_accepted(
    era, serve, drive
):
    found = drive(
        serve(Policy(), era=era, unauthorized_method="tools/call"),
        "foreign_audience",
        jwt(aud=ELSEWHERE),
    )

    assert found.code == 0, found.err
    assert verdict.read(found.path).state == verdict.COMPLETE
    by_role = collections.defaultdict(list)
    for x in found.exchanges:
        by_role[x["role"]].append(x["accepted"])
    # ``server/discover`` is the era probe only where ``initialize`` follows, in the legacy era.
    assert by_role["era_probe"] == ([None] if era == "legacy" else [])
    assert by_role["opening"] == [True]
    assert by_role["list"] == [True] and by_role["call"] == [False]
    assert found.exchanges[-1]["role"] == "call"
    assert found.exchanges[-1]["http_status"] == 401
    assert found.exchanges[-1]["rpc_code"] == -32001
    assert found.of("step_called"), "the call was sent, and its refusal is the exchange"
    assert found.of("step_unanswered") == [] and found.of("server_failed") == []
    assert found.of("script_finished")[0]["inventory"] == "partial"
    lines = found.out.splitlines()
    assert len(lines) == len(found.exchanges)
    assert lines[-1] == "tools/call\tcall\trejected\tstatus 401\tcode -32001"


def test_the_era_probe_is_an_exchange_of_its_own_and_the_line_says_so(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True)), "no_token")

    (probe,) = found.in_role("era_probe")
    assert (probe["method"], probe["accepted"], probe["http_status"]) == (
        "server/discover", None, 400,
    )  # fmt: skip
    assert probe["rpc_code"] == -32600
    assert found.out.splitlines()[0] == (
        "server/discover\tera_probe (era detection)\tneither\tstatus 400\tcode -32600"
    )


def test_the_event_is_written_before_the_end_of_the_run(serve, drive):
    found = drive(serve(Policy(), deny_status=403), "no_token")

    kinds = [e["type"] for e in found.events]
    assert kinds.index("token_observation") < kinds.index("script_finished")
    assert kinds.index("script_finished") < kinds.index("run_finished")


def test_the_terminal_says_what_the_exchanges_were_and_does_not_judge(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True)), "no_token")

    assert found.out.splitlines()[-1] == "tools/call\tcall\taccepted\tstatus 200\tcode -"
    assert "initialize\topening\taccepted\tstatus 200\tcode -" in found.out.splitlines()
    for word in ("fail", "pass", "vulnerab", "secure", "good", "bad"):
        assert word not in found.out.lower()


# -- nothing on stderr about the refusal -----------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_a_refusal_is_not_judged_on_stderr(kind, serve, drive):
    token, policy = KINDS[kind]
    found = drive(serve(policy), kind, token())

    assert "rejected" in found.out
    for word in ("unauthorized", "obtain a token", "--token-file", "401"):
        assert word not in found.err


def test_without_a_mark_the_hint_to_obtain_a_token_stays(serve, drive):
    found = drive(serve(Policy(audience=SERVED)), None, jwt(aud=ELSEWHERE, exp=in_an_hour()))

    assert "unauthorized (401)" in found.err and "obtain a token" in found.err


# -- every request sent has its entry --------------------------------------------------------------


def test_a_call_answered_500_is_an_exchange_neither_with_its_status(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), statuses={"tools/call": 500}), "no_token")

    (call,) = found.in_role("call")
    assert (call["method"], call["accepted"], call["http_status"], call["rpc_code"]) == (
        "tools/call", None, 500, None,
    )  # fmt: skip
    assert found.out.splitlines()[-1] == "tools/call\tcall\tneither\tstatus 500\tcode -"


def test_a_list_answered_429_without_retry_after_is_an_exchange_neither_with_its_status(
    serve, drive
):
    found = drive(serve(Policy(anonymous_ok=True), statuses={"tools/list": 429}), "no_token")

    (listing,) = found.in_role("list")
    assert (listing["accepted"], listing["http_status"], listing["rpc_code"]) == (None, 429, None)
    assert found.in_role("call") == [], "the run ended at the list, which drew no answer to read"


def test_a_request_that_is_never_answered_is_an_exchange_with_no_answer(serve, drive):
    stalling = serve(Policy(anonymous_ok=True), stall="tools/call")
    found = drive(stalling, "no_token", None, "--step-timeout", "2")

    (call,) = found.in_role("call")
    assert (call["method"], call["accepted"], call["http_status"], call["rpc_code"]) == (
        "tools/call", None, None, None,
    )  # fmt: skip
    assert found.in_role("list")[0]["accepted"] is True
    assert found.out.splitlines()[-1] == "tools/call\tcall\tno answer"


# -- a wait for Retry-After after which nothing is sent ------------------------------------------


@pytest.fixture
def limited():
    """``limited(limits)``: a server of ``http_limits``, which answers each of ``limits`` once with
    its status before it answers anything else; ``posts`` lists the method of every POST."""
    started = []
    posts: list[str | None] = []

    def start(limits):
        server = http_limits.serve(limits, call_result="text")
        handler = server.RequestHandlerClass

        class Counting(handler):
            def do_POST(self):  # noqa: N802 - the name http.server calls
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                posts.append(json.loads(body).get("method"))
                self.rfile = io.BytesIO(body)  # the handler reads the body itself
                super().do_POST()

        server.RequestHandlerClass = Counting
        started.append(server)
        return server

    start.posts = posts
    yield start
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.fixture
def rolling(monkeypatch):
    """The driver's monotonic clock and its wait as one: a sleep moves the clock on by the seconds
    asked and ``overshoot`` more, then runs ``then``; nothing really waits."""
    state = types.SimpleNamespace(now=1000.0, overshoot=0.0, slept=[], then=lambda: None)

    async def sleep(seconds):
        state.slept.append(seconds)
        state.now += seconds + state.overshoot
        state.then()

    monkeypatch.setattr(driver, "_monotonic", lambda: state.now)
    monkeypatch.setattr(driver, "_sleep", sleep)
    return state


#: The list answered 429 with a wait of 29 s, in a step of 30 s.
LIMITED_LIST = [("tools/list", 429, {"Retry-After": "29"})]

#: The one exchange the list is, sent once: the 429 of the first and only request.
LIMITED_EXCHANGE = {
    "role": "list",
    "method": "tools/list",
    "accepted": None,
    "http_status": 429,
    "rpc_code": None,
}


def test_a_wait_that_leaves_no_time_notes_the_list_once_with_its_429(limited, drive, rolling):
    rolling.overshoot = 1.0  # the wait takes all that was left of the step

    found = drive(limited(LIMITED_LIST), "no_token", None, "--step-timeout", "30")

    assert rolling.slept == [29]
    assert limited.posts.count("tools/list") == 1, "the request was not sent again"
    assert [x for x in found.exchanges if x["method"] == "tools/list"] == [LIMITED_EXCHANGE]
    assert ("tools/list", "rate_limited") in [
        (e["step"], e["reason"]) for e in found.of("step_unanswered")
    ]
    assert found.in_role("opening")[0]["accepted"] is True


def test_a_halt_in_the_wait_notes_the_list_once_with_its_429(limited, drive, rolling, tmp_path):
    # The file the fixture writes for its first run: the stop file appears in the wait.
    held = tmp_path / "run1" / "engagement" / "acme-2026-10.json"
    rolling.then = lambda: engagement.stop_path(held).write_text("stop\n")

    found = drive(limited(LIMITED_LIST), "no_token", None, "--step-timeout", "30")

    assert rolling.slept == [29]
    assert limited.posts.count("tools/list") == 1, "no request goes out on a halt"
    assert [x for x in found.exchanges if x["method"] == "tools/list"] == [LIMITED_EXCHANGE]
    assert found.in_role("call") == [], "nothing after the halt was sent"
    assert ("tools/list", "run_halted") in found.skipped
    (finished,) = found.of("run_finished")
    assert finished["reason"] == "stop_file"


# -- the code of a refusal -------------------------------------------------------------------------


def test_a_401_with_a_json_rpc_error_in_the_body_has_its_code(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), unauthorized_method="tools/call"), "no_token")

    assert found.in_role("call")[0]["rpc_code"] == -32001
    assert not found.in_role("call")[0]["accepted"]


#: A known value of the engagement made of digits, which a server may put where a code goes.
KNOWN_NUMBER = "4711"


def replaced_known(found: Run) -> int:
    (finished,) = found.of("run_finished")
    return finished["replacements"]["known"]


@pytest.mark.parametrize("where", ["error_200", "body_401"])
def test_a_known_value_as_a_code_is_no_code_and_is_counted_once(where, awkward, drive):
    """The test of a code is the recorder's (``recorder.wire_code``): a known value of digits is
    no code in the observation or on stdout, and asking does not count it again."""
    token = "tk" + secrets.token_hex(8)
    server = (
        awkward(Policy(), code_method="tools/call", echo=KNOWN_NUMBER)
        if where == "error_200"
        else awkward(Policy(), unauthorized_method="tools/call", mirror=True, echo=KNOWN_NUMBER)
    )

    found = drive(server, "foreign_audience", token, known=(KNOWN_NUMBER,))
    unmarked = drive(server, None, token, known=(KNOWN_NUMBER,))

    (call,) = found.in_role("call")
    assert call["accepted"] is (False if where == "body_401" else None)
    assert call["rpc_code"] is None
    assert int(KNOWN_NUMBER) not in [x["rpc_code"] for x in found.exchanges]
    assert KNOWN_NUMBER not in found.out + found.err
    assert found.out.splitlines()[-1].endswith("\tcode -")
    # The same run without the mark never asks: the known value was counted as often.
    assert replaced_known(found) == replaced_known(unmarked) > 0


def test_a_401_without_a_json_body_has_no_code(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), statuses={"tools/call": 401}), "no_token")

    (call,) = found.in_role("call")
    assert (call["accepted"], call["http_status"], call["rpc_code"]) == (False, 401, None)
    assert found.out.splitlines()[-1] == "tools/call\tcall\trejected\tstatus 401\tcode -"


def test_nothing_of_the_body_of_a_refusal_but_its_number_is_recorded(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), unauthorized_method="tools/call"), "no_token")

    # The wire recording holds the body as it always did; the observation, stdout and stderr do not.
    assert "not authorized" not in json.dumps(found.of("token_observation"))
    assert "not authorized" not in found.out + found.err


# -- a probe module --------------------------------------------------------------------------------


def test_a_probe_run_that_is_rejected_after_the_opening_skips_the_rest_with_its_own_reason(
    serve, drive
):
    found = drive(
        serve(Policy(anonymous_ok=True), unauthorized_method="tools/list"),
        "no_token",
        probe=True,
    )

    assert found.code == 0, found.err
    assert found.roles() == ["era_probe", "opening", "probe"]
    assert [x["accepted"] for x in found.exchanges] == [None, True, False]
    assert found.exchanges[-1]["method"] == "tools/list"
    assert found.skipped == [("probe", "observation_rejected")]
    assert "not sent" in found.of("step_skipped")[0]["detail"]
    assert found.of("step_unanswered") == [] and found.of("server_failed") == []
    assert verdict.read(found.path).state == verdict.COMPLETE


def test_a_probe_run_that_is_accepted_has_its_requests_as_probe(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True)), "no_token", probe=True)

    assert found.roles() == ["era_probe", "opening", "probe", "probe"]
    assert [x["accepted"] for x in found.exchanges] == [None, True, True, True]
    assert found.skipped == []


# -- the expiry ------------------------------------------------------------------------------------


def test_an_expired_token_says_so_and_the_event_carries_expiry(serve, drive):
    found = drive(serve(Policy(check_exp=True)), "expired", jwt(aud=SERVED, exp=long_ago()))

    (observed,) = found.of("token_observation")
    assert observed["expiry"] == "expired" and found.started["auth"]["token"]["expired"] is True
    assert "the token was expired when the run began" in found.err


def test_a_token_that_is_still_valid_goes_on_and_the_output_says_it(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True)), "expired", jwt(aud=SERVED, exp=in_an_hour()))

    (observed,) = found.of("token_observation")
    assert (
        observed["expiry"] == "not_expired" and found.started["auth"]["token"]["expired"] is False
    )
    assert found.of("step_called"), "the run went on"
    assert "not expired when the run began; the run went on" in found.err


def test_the_expiry_is_reckoned_by_the_clock_of_the_recording(serve, drive, monkeypatch):
    token = jwt(aud=SERVED, exp=in_an_hour())
    later = datetime.now(timezone.utc) + timedelta(hours=3)
    monkeypatch.setattr(recorder, "utc_now", lambda: later)
    found = drive(serve(Policy(anonymous_ok=True)), "expired", token)

    assert found.of("token_observation")[0]["expiry"] == "expired"
    assert found.started["auth"]["token"]["expired"] is True


def test_an_opaque_token_cannot_be_checked_and_the_output_says_whose_word_that_is(serve, drive):
    found = drive(serve(Policy()), "expired", "opaque-" + secrets.token_hex(24))

    (observed,) = found.of("token_observation")
    assert observed["expiry"] == "not_checkable"
    assert found.started["auth"]["token"]["expired"] is None
    assert "expiry as declared by the engagement, not checkable" in found.err


@pytest.mark.parametrize("kind", ["foreign_audience", "no_token"])
def test_the_other_kinds_have_no_expiry(kind, serve, drive):
    token, _ = KINDS[kind]
    found = drive(serve(Policy(anonymous_ok=True)), kind, token())

    assert "expiry" not in found.of("token_observation")[0]


# -- without the mark, the same refusal is what it was ---------------------------------------------


def test_the_same_refusal_without_a_mark_ends_as_unauthorized_as_before(serve, drive):
    found = drive(serve(Policy(audience=SERVED)), None, jwt(aud=ELSEWHERE, exp=in_an_hour()))

    assert found.code == 4
    assert found.started["auth"]["observation"] is None
    assert found.of("token_observation") == []
    (failed,) = found.of("server_failed")
    assert failed["reason"] == "unauthorized"
    assert {reason for _, reason in found.skipped} == {"unauthorized"}
    assert "unauthorized" in verdict.read(found.path).causes
    assert "rejected" not in found.out


# -- the rule, on recordings -----------------------------------------------------------------------


def recording(observation, *more) -> list[dict]:
    seq = {"v": events.SCHEMA_VERSION}
    started = {
        **seq, "type": "run_started", "schema_version": events.SCHEMA_VERSION, "mode": "driver",
        "isolation": "host", "transport": "streamable-http",
        "auth": None if observation is False else {"observation": observation},
    }  # fmt: skip
    counted = {"exchanges": 1, "responses": {"4xx": 1}, "streams": 0, "events": 0,
               "framing_errors": 0}  # fmt: skip
    ended = {
        **seq, "type": "run_finished", "findings_by_statement": {}, "http": counted,
        "server_output_bytes": 10, "client_input_bytes": 10, "server_exited_first": False,
    }  # fmt: skip
    script = {**seq, "type": "script_finished", "inventory": "none"}
    return [started, *[{**seq, **event} for event in more], script, ended]


SKIPPED = {"type": "step_skipped", "step": "tools/list", "reason": "observation_rejected"}


def test_rule_14_steps_skipped_for_a_rejection_are_no_gap_in_an_observation():
    judged = verdict.judge(recording("no_token", SKIPPED))

    assert judged.state == verdict.COMPLETE and judged.causes == []


def test_rule_14_without_observation_such_a_step_is_one_that_was_not_sent():
    for auth in (False, None):
        judged = verdict.judge(recording(auth, SKIPPED))
        assert judged.state == verdict.INCOMPLETE and judged.causes == ["step_not_sent"]


@pytest.mark.parametrize(
    ("event", "cause"),
    [
        ({"type": "step_skipped", "step": "tools/list", "reason": "rate_limited"}, "step_not_sent"),
        ({"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": "rate_limited"},
         "rate_limited"),
        ({"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": "no_answer"},
         "step_unanswered"),
        ({"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": "unauthorized"},
         "unauthorized"),
        ({"type": "server_failed", "reason": "http_unreachable"}, "http_unreachable"),
    ],
)  # fmt: skip
def test_rule_14_every_other_cause_of_an_observation_stands(event, cause):
    judged = verdict.judge(recording("expired", SKIPPED, event))

    assert cause in judged.causes and judged.state != verdict.COMPLETE


def silent(events_: list[dict]) -> list[dict]:
    """The recording as the proxy counts a refusal with no body byte: nothing from the server."""
    return [*events_[:-1], {**events_[-1], "server_output_bytes": 0}]


def refusal(status: int | None = 401, accepted: bool | None = False) -> dict:
    exchange = {"method": "server/discover", "accepted": accepted, "http_status": status,
                "rpc_code": None}  # fmt: skip
    return {"type": "token_observation", "kind": "no_token", "exchanges": [exchange]}


@pytest.mark.parametrize("status", [401, 403])
def test_rule_14_goes_before_the_check_for_silence(status):
    judged = verdict.judge(silent(recording("no_token", refusal(status), SKIPPED)))

    assert judged.state == verdict.COMPLETE and judged.causes == []


@pytest.mark.parametrize(
    ("observation", "more"),
    [
        (False, [refusal(), SKIPPED]),  # no mark: the refusal is unauthorized, as under 12
        ("no_token", [SKIPPED]),  # no exchange refused
        ("no_token", [refusal(), ]),  # the run did not end for it: no step skipped for it
        ("no_token", [refusal(200, True), SKIPPED]),  # accepted
        ("no_token", [refusal(429, None), SKIPPED]),  # neither: a limit, not a refusal
        ("no_token", [refusal(500, None), SKIPPED]),
        ("no_token", [refusal(None, None), SKIPPED]),  # no answer
        ("no_token", [refusal(401, None), SKIPPED]),  # a 401 not called a refusal
    ],
)  # fmt: skip
def test_rule_14_is_narrow_and_the_silence_stands_otherwise(observation, more):
    judged = verdict.judge(silent(recording(observation, *more)))

    assert "server_silent" in judged.causes and judged.state == verdict.SERVER_FAILED


def test_the_rules_are_version_14():
    assert verdict.RULES_VERSION == 14


# -- the engagement file ---------------------------------------------------------------------------

TOKEN_SOURCES = {
    "env": {"token_env": "SOME_VARIABLE"},
    "file": {"token_file": "tokens/some"},
    "none": {"token": "none"},
}


def file_with(tmp_path: Path, version_two: bool = True, **fields) -> Path:
    named = {"name": "observer", "role": "observation", **fields}
    if version_two:
        return second_file(tmp_path, identities=[named])
    from test_cli_engagement import write_engagement

    return write_engagement(tmp_path, identities=[named])


@pytest.mark.parametrize(
    ("kind", "source"),
    [
        ("foreign_audience", "env"),
        ("foreign_audience", "file"),
        ("expired", "env"),
        ("expired", "file"),
        ("no_token", "none"),
    ],
)
def test_a_kind_with_the_source_it_goes_with_is_read(tmp_path, kind, source):
    held = engagement.load(file_with(tmp_path, observation=kind, **TOKEN_SOURCES[source]))

    assert [i.observation for i in held.identities] == [kind]


def test_an_identity_without_a_mark_has_none(tmp_path):
    held = engagement.load(file_with(tmp_path, **TOKEN_SOURCES["env"]))

    assert held.identities[0].observation is None


@pytest.mark.parametrize(
    ("kind", "source"),
    [
        ("no_token", "env"),
        ("no_token", "file"),
        ("foreign_audience", "none"),
        ("expired", "none"),
    ],
)
def test_a_kind_with_the_wrong_source_is_refused_with_the_field(tmp_path, kind, source):
    with pytest.raises(engagement.EngagementError) as refused:
        engagement.load(file_with(tmp_path, observation=kind, **TOKEN_SOURCES[source]))

    assert "identities[0].observation" in str(refused.value)


@pytest.mark.parametrize(
    "value",
    ["revoked", "tok-" + secrets.token_hex(8), "Expired", "", 1, True, ["expired"], {"a": 1}],
)
def test_a_value_that_is_no_kind_is_refused_with_the_field_and_without_the_value(tmp_path, value):
    with pytest.raises(engagement.EngagementError) as refused:
        engagement.load(file_with(tmp_path, observation=value, **TOKEN_SOURCES["env"]))

    assert "identities[0].observation" in str(refused.value)
    if isinstance(value, str) and value:
        assert value not in str(refused.value)


def test_in_the_first_version_observation_is_an_unknown_key_as_it_was(tmp_path):
    with pytest.raises(engagement.EngagementError) as refused:
        engagement.load(file_with(tmp_path, False, observation="expired", **TOKEN_SOURCES["env"]))

    assert "identities[0]" in str(refused.value) and "unknown key 'observation'" in str(
        refused.value
    )


def test_the_kinds_of_the_file_are_those_of_the_recording():
    assert engagement.OBSERVATIONS == events.TOKEN_OBSERVATIONS


def test_show_names_the_mark_of_each_identity(tmp_path, capsys):
    held = second_file(
        tmp_path,
        identities=[
            {"name": "a", "role": "r", "token_env": "VAR_A", "observation": "expired"},
            {"name": "b", "role": "r", "token": "none", "observation": "no_token"},
            {"name": "c", "role": "r", "token_env": "VAR_C"},
        ],
    )

    assert cli.main(["engagement", "show", str(held)]) == 0
    shown = capsys.readouterr()
    lines = (shown.out + shown.err).splitlines()
    assert any("VAR_A" in line and "observation: expired" in line for line in lines)
    assert any("no token" in line and "observation: no_token" in line for line in lines)
    assert [line for line in lines if "VAR_C" in line and "observation" in line] == []


def test_an_identity_without_a_mark_is_no_observation(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True)), None, jwt(aud=SERVED))

    assert found.started["auth"]["observation"] is None
    assert found.of("token_observation") == []
    assert found.out == ""


# -- no token in any artifact ----------------------------------------------------------------------


def test_no_artifact_holds_a_byte_of_the_token_a_part_of_it_or_a_piece_of_base64(
    tmp_path, serve, drive, monkeypatch
):
    token, parts = made_up_jwt({"aud": ELSEWHERE, "exp": in_an_hour()})
    reflecting = serve(Policy(audience=SERVED), reflect=("Authorization",))
    found = [drive(reflecting, "foreign_audience", token)]
    # An observation the server accepts, and one refused at the gate (a flag beside an identity).
    found.append(drive(serve(Policy(), reflect=("Authorization",)), "foreign_audience", token))
    refused = tmp_path / "refused"
    held = second_file(refused / "engagement", identities=[identity("foreign_audience")])
    err, out = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
        code = cli.main(
            ["drive", "--engagement", str(held), "--out-dir", str(refused / "runs"), "--http",
             f"http://127.0.0.1:{reflecting.server_address[1]}{http_server.PATH}",
             "--identity", "observer", "--token-env", TOKEN_ENV]
        )  # fmt: skip
    assert code == 2

    artifacts = [(str(path), path.read_bytes()) for path in sorted(tmp_path.rglob("*"))
                 if path.is_file()]  # fmt: skip
    artifacts += [(f"{n}.stdout", run.out.encode()) for n, run in enumerate(found)]
    artifacts += [(f"{n}.stderr", run.err.encode()) for n, run in enumerate(found)]
    artifacts.append(("refused.stderr", err.getvalue().encode()))
    artifacts.append(("refused.stdout", out.getvalue().encode()))
    assert any(label.endswith("refusals.jsonl") for label, _ in artifacts)
    assert any(label.endswith("events.jsonl") for label, _ in artifacts)
    holding = [
        (label, piece)
        for piece in pieces(parts, token)
        for label, content in artifacts
        if piece.encode() in content
    ]
    assert holding == []


# -- when an exchange is accepted ------------------------------------------------------------------

REJECTIONS = ["stall", "abort", "not_json", "result"]
# What a run may take beyond the wait for the body of a refusal: the rest of the run.
ROOM = 3.0


@pytest.mark.parametrize("rejection", REJECTIONS)
@pytest.mark.parametrize("status", [401, 403])
def test_a_refusal_is_rejected_whatever_becomes_of_its_body(rejection, status, awkward, drive):
    began = time.monotonic()
    found = drive(awkward(Policy(), rejection=rejection, deny_status=status), "no_token")
    took = time.monotonic() - began

    (exchange,) = found.exchanges
    assert (exchange["accepted"], exchange["http_status"], exchange["rpc_code"]) == (
        False, status, None,
    )  # fmt: skip
    assert found.skipped == [
        ("tools/list", "observation_rejected"),
        ("tools/call", "observation_rejected"),
    ]
    assert found.of("server_failed") == [] and found.of("step_unanswered") == []
    assert f"rejected\tstatus {status}\tcode -" in found.out
    assert took < REJECTION_BODY_SECONDS + ROOM
    if rejection != "stall":
        assert verdict.read(found.path).state == verdict.COMPLETE


# A refusal with no body byte at all is the usual answer of a real server, and the proxy counts
# nothing of it (``server_output_bytes`` counts body bytes). Rule 14 goes before the check for
# silence, for an observation that ended with a refusal.
BODILESS = ["stall", "empty", "html"]


@pytest.mark.parametrize("rejection", BODILESS)
@pytest.mark.parametrize("status", [401, 403])
def test_a_refusal_whose_body_never_comes_is_complete(rejection, status, awkward, drive):
    found = drive(awkward(Policy(), rejection=rejection, deny_status=status), "no_token")

    assert found.exchanges[0]["accepted"] is False
    # The proxy counts the body bytes of the answer; a text/html body has some, the others none.
    assert (found.of("run_finished")[0]["server_output_bytes"] == 0) == (rejection != "html")
    judged = verdict.read(found.path)
    assert judged.state == verdict.COMPLETE
    assert judged.causes == []
    # The exit code follows the state (rule 14), though the proxy counted the silence.
    assert judged.refused and found.code == 0


@pytest.mark.parametrize("rejection", BODILESS)
@pytest.mark.parametrize("status", [401, 403])
def test_without_a_mark_the_same_refusal_ends_as_it_did(rejection, status, awkward, drive):
    found = drive(
        awkward(Policy(audience=SERVED), rejection=rejection, deny_status=status),
        None,
        jwt(aud=ELSEWHERE, exp=in_an_hour()),
    )

    # As it ended before: the state and the cause. A text/html body is a body byte the proxy counts.
    judged = verdict.read(found.path)
    assert judged.state == verdict.SERVER_FAILED
    assert "unauthorized" in judged.causes
    assert ("server_silent" in judged.causes) == (rejection != "html")
    assert found.code == 4


def test_an_observation_whose_server_is_silent_without_refusing_is_server_failed(awkward, drive):
    found = drive(awkward(Policy(), bodiless=True), "no_token")

    judged = verdict.read(found.path)
    assert judged.state == verdict.SERVER_FAILED
    assert "server_silent" in judged.causes
    assert found.of("run_finished")[0]["server_output_bytes"] == 0
    assert all(x["accepted"] is not False for x in found.exchanges)
    assert not judged.refused and found.code == 4


@pytest.mark.parametrize("status", [401, 403])
def test_a_refusal_in_a_recording_without_its_end_is_not_rule_14(status):
    whole = recording("no_token", refusal(status), SKIPPED)

    assert verdict.judge(silent(whole)).refused
    # The end never reached the disk: the condition does not hold, and the silence counts.
    assert not verdict.judge(whole[:-1]).refused


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize(("whole", "code"), [(True, 0), (False, verdict.EXIT_SERVER_FAILED)])
def test_the_exit_of_a_silent_refused_observation_follows_whether_its_end_reached_the_disk(
    status, whole, code, tmp_path
):
    # The process saw the server silent. With the end of the run on disk the refusal is rule 14's
    # and the run exits 0; without it the silence counts, as it did before rule 14.
    written = silent(recording("no_token", refusal(status), SKIPPED))
    if not whole:
        written = written[:-1]
    assert [e["type"] for e in written].count("run_finished") == int(whole)
    path = tmp_path / "events.jsonl"
    path.write_text("".join(json.dumps(event) + "\n" for event in written))
    view = cli.TerminalView(io.StringIO(), quiet=True)
    seen = types.SimpleNamespace(sandbox_failed=None, server_failed=None, server_silent=True)

    assert cli._driven_exit(view, path, seen, None) == code


@pytest.mark.parametrize("rejection", ["stall", "abort"])
def test_a_refusal_stands_when_the_step_ends_with_the_wait_for_its_body(rejection, awkward, drive):
    # The shortest step there is, the time of the wait for the body: whichever ends first, the
    # refusal is what the head said.
    found = drive(awkward(Policy(), rejection=rejection), "no_token", None, "--step-timeout", "2")

    (exchange,) = found.exchanges
    assert (exchange["accepted"], exchange["http_status"]) == (False, 401)
    assert found.of("server_failed") == [] and found.of("step_unanswered") == []
    assert found.skipped == [
        ("tools/list", "observation_rejected"),
        ("tools/call", "observation_rejected"),
    ]


# The wait for the body is made long (6 s) for this test, the step is given 3 s and the head of
# the refusal comes after 1.5 s: a second and a half for the head to arrive within the step on a
# machine under load, a second and a half of slack after the step. Waited in full, the step would
# end after 7.5 s; the body is held back longer than that (``LONG_STALL_SECONDS``).
BODY_SECONDS = 6.0
STEP_SECONDS = 3.0
HEAD_DELAY = 1.5
SLACK = 1.5


def test_the_wait_for_the_body_of_a_refusal_ends_with_the_rest_of_the_step(
    awkward, drive, monkeypatch
):
    monkeypatch.setattr(http_client, "REJECTION_BODY_SECONDS", BODY_SECONDS)
    assert HEAD_DELAY + BODY_SECONDS > STEP_SECONDS + SLACK + 2
    assert rejecting_server.LONG_STALL_SECONDS > HEAD_DELAY + BODY_SECONDS
    server = awkward(Policy(), rejection="long_stall", head_delay=HEAD_DELAY)
    found = drive(server, "no_token", None, "--step-timeout", str(STEP_SECONDS))

    (exchange,) = found.exchanges
    assert (exchange["accepted"], exchange["http_status"], exchange["rpc_code"]) == (
        False, 401, None,
    )  # fmt: skip
    # The first step skipped for the refusal is written when the refused step has ended; the
    # clock of the recording starts with the run. (The end of the run comes later: the closing of
    # the connection is not part of the step.)
    ended = found.of("step_skipped")[0]["t_ns"] / 1e9
    assert ended < STEP_SECONDS + SLACK, ended
    assert found.skipped == [
        ("tools/list", "observation_rejected"),
        ("tools/call", "observation_rejected"),
    ]


@pytest.mark.parametrize("rejection", ["long_stall", "drip"])
@pytest.mark.parametrize("status", [401, 403])
def test_the_step_ends_with_the_wait_for_the_body_of_a_refusal(rejection, status, awkward, drive):
    # The server holds the body for 8 s (a stall) or 10 s (a byte every 0.3 s): with the old
    # wait of 10 s the step would take as long.
    assert rejecting_server.LONG_STALL_SECONDS >= 8 and rejecting_server.DRIP_SECONDS >= 10
    found = drive(awkward(Policy(), rejection=rejection, deny_status=status), "no_token")

    (finished,) = found.of("run_finished")
    took = finished["duration_ns"] / 1e9
    assert REJECTION_BODY_SECONDS <= 2  # the bound below is not loosened with the wait
    assert took <= REJECTION_BODY_SECONDS + 1.5
    (exchange,) = found.exchanges
    assert (exchange["accepted"], exchange["http_status"], exchange["rpc_code"]) == (
        False, status, None,
    )  # fmt: skip
    assert found.skipped == [
        ("tools/list", "observation_rejected"),
        ("tools/call", "observation_rejected"),
    ]


def test_the_wait_for_the_body_of_a_refusal_is_short():
    assert 0 < REJECTION_BODY_SECONDS <= 2


@pytest.mark.parametrize("rejection", [None, *REJECTIONS])
@pytest.mark.parametrize("status", [401, 403])
def test_without_a_mark_the_body_of_a_refusal_is_not_read_and_the_run_is_unauthorized(
    rejection, status, awkward, drive
):
    began = time.monotonic()
    found = drive(
        awkward(Policy(audience=SERVED), rejection=rejection, deny_status=status),
        None,
        jwt(aud=ELSEWHERE, exp=in_an_hour()),
    )

    assert found.code == 4
    assert [e["reason"] for e in found.of("server_failed")] == ["unauthorized"]
    assert "unauthorized" in verdict.read(found.path).causes
    assert found.of("token_observation") == []
    # A stalling body would hold the run for as long as the server stalls.
    assert time.monotonic() - began < rejecting_server.STALL_SECONDS


def test_a_200_with_a_result_is_accepted_and_a_200_with_an_error_is_neither(awkward, drive):
    found = drive(awkward(Policy(anonymous_ok=True), code_method="tools/call"), "no_token")

    assert found.in_role("list")[0]["accepted"] is True
    (call,) = found.in_role("call")
    assert (call["accepted"], call["http_status"], call["rpc_code"]) == (None, 200, -32001)
    assert found.out.splitlines()[-1] == "tools/call\tcall\tneither\tstatus 200\tcode -32001"


# A 200 whose answer holds a ``result`` and an ``error`` at once is no valid JSON-RPC result, for
# every role a request has: neither, with the code of its error. The era probe of a server with
# both sides is matched by a null id as well, as the body of a 400 is.
BOTH = {
    "call": ("legacy", "tools/call", False),
    "list": ("legacy", "tools/list", False),
    "opening": ("legacy", "initialize", False),
    "opening_modern": ("modern", "server/discover", False),
    "era_probe": ("dual", "server/discover", True),
    "probe": ("legacy", "tools/call", False),
}


@pytest.mark.parametrize("case", sorted(BOTH))
def test_a_200_with_both_a_result_and_an_error_is_neither_with_its_code(case, awkward, drive):
    era, method, null_id = BOTH[case]
    role = case.removesuffix("_modern")
    server = awkward(Policy(anonymous_ok=True), era=era, both_method=method, both_null_id=null_id)
    found = drive(server, "no_token", probe=role == "probe")

    (exchange, *_) = [x for x in found.exchanges if x["method"] == method and x["role"] == role]
    assert (exchange["accepted"], exchange["http_status"], exchange["rpc_code"]) == (
        None, 200, -32001,
    )  # fmt: skip
    line = [entry for entry in found.out.splitlines() if entry.startswith(f"{method}\t")]
    assert any("\tneither\tstatus 200\tcode -32001" in entry for entry in line), found.out
    assert not any("\taccepted\t" in entry and "code -32001" in entry for entry in line)
    # The steps read a call's answer as the SDKs do, the result first: no call_failed for it.
    assert found.of("call_failed") == []


def test_a_call_whose_result_is_a_tool_error_beside_an_error_is_that_tool_error(awkward, drive):
    # The step reads the call by its result, as any call: ``isError: true`` is a tool error. The
    # error beside it adds no call_failed of its own; the exchange is neither, with its code.
    failing = {"content": [{"type": "text", "text": "no"}], "isError": True}
    server = awkward(Policy(anonymous_ok=True), both_method="tools/call", both_result=failing)
    found = drive(server, "no_token")

    (call,) = found.in_role("call")
    assert (call["accepted"], call["http_status"], call["rpc_code"]) == (None, 200, -32001)
    assert [(e["tool"], e["kind"]) for e in found.of("call_failed")] == [
        ("tool_0", events.CALL_TOOL_ERROR)
    ]


def test_a_call_whose_result_and_error_are_no_objects_is_unreadable(awkward, drive):
    # Neither a result object nor an error object: nothing can be read out of the answer. The
    # step says so and no call_failed is recorded; the exchange is neither, without a code.
    server = awkward(
        Policy(anonymous_ok=True), both_method="tools/call", both_result="x", both_error="failed"
    )
    found = drive(server, "no_token")

    (call,) = found.in_role("call")
    assert (call["accepted"], call["http_status"], call["rpc_code"]) == (None, 200, None)
    assert [(e["step"], e["reason"]) for e in found.of("step_unanswered")] == [
        ("tools/call", "answer_unreadable")
    ]
    assert found.of("call_failed") == []


# An ``error`` key beside a valid result makes the answer no result, even ``"error": null``: as
# the recording's own message analysis reads it (``events.analyse``). Neither, and no code.
NULL_ERROR = {case: BOTH[case] for case in ("call", "list", "opening", "opening_modern")}


@pytest.mark.parametrize("case", sorted(NULL_ERROR))
def test_a_200_with_a_result_and_a_null_error_is_neither(case, awkward, drive):
    era, method, _ = NULL_ERROR[case]
    role = case.removesuffix("_modern")
    server = awkward(Policy(anonymous_ok=True), era=era, both_method=method, both_error=None)
    found = drive(server, "no_token")

    (exchange, *_) = [x for x in found.exchanges if x["method"] == method and x["role"] == role]
    assert (exchange["accepted"], exchange["http_status"], exchange["rpc_code"]) == (
        None, 200, None,
    )  # fmt: skip
    assert f"{method}\t{role}\tneither\tstatus 200\tcode -" in found.out.splitlines()


@pytest.mark.parametrize("error", ["failed", -32001, [], {}])
def test_a_200_with_a_result_and_any_other_error_value_is_neither(error, awkward, drive):
    server = awkward(Policy(anonymous_ok=True), both_method="tools/call", both_error=error)
    found = drive(server, "no_token")

    (call,) = found.in_role("call")
    # Only an error object has a code to keep.
    assert (call["accepted"], call["http_status"], call["rpc_code"]) == (None, 200, None)


def test_a_429_is_neither_and_a_request_without_an_answer_is_no_answer(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), statuses={"tools/list": 429}), "no_token")
    assert (found.in_role("list")[0]["accepted"], found.in_role("list")[0]["http_status"]) == (
        None, 429,
    )  # fmt: skip

    found = drive(
        serve(Policy(anonymous_ok=True), stall="tools/call"),
        "no_token",
        None,
        "--step-timeout",
        "2",
    )
    assert found.in_role("call")[0]["accepted"] is None
    assert found.out.splitlines()[-1] == "tools/call\tcall\tno answer"


def test_the_era_probe_of_a_legacy_server_is_neither(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), era="legacy"), "no_token")

    (probe,) = found.in_role("era_probe")
    assert (probe["accepted"], probe["http_status"]) == (None, 400)


# -- a number the server names ---------------------------------------------------------------------


def a_driver(**more) -> driver.Driver:
    script = dataclasses.replace(driver.DISCOVERY, steps=())
    return driver.Driver(script, None, record_skipped=None, **more)


@pytest.mark.parametrize("code", [2**31 + 1, -(2**31) - 1, 10**30, True, 1.5, "7", None])
def test_a_code_out_of_bounds_or_of_another_type_is_not_recorded(code):
    assert a_driver()._code(code) is None


def test_a_code_within_the_bounds_is_kept_and_one_that_is_a_literal_is_not():
    held = a_driver(is_literal=lambda number: number == 424242)

    assert held._code(-32001) == -32001 and held._code(2**31) == 2**31
    assert held._code(424242) is None


@pytest.mark.parametrize("status", [0, 99, 600, 1000, -1, True, None, "200"])
def test_a_status_outside_100_to_599_is_not_recorded(status):
    assert driver._http_status(status) is None


class Bare:
    """What ``Recorder.token_observation`` needs of a recorder: somewhere to put the event."""

    def _emit(self, *_args) -> None:
        raise AssertionError("an exchange with such a code is not written")


@pytest.mark.parametrize("code", [events.MAX_RPC_CODE + 1, -events.MAX_RPC_CODE - 1])
def test_the_recording_refuses_a_code_beyond_the_bound(code):
    exchange = {"role": "call", "method": "tools/call", "accepted": None, "http_status": 200}

    with pytest.raises(ValueError):
        recorder.Recorder.token_observation(
            Bare(), 1, 1, kind="no_token", exchanges=[{**exchange, "rpc_code": code}]
        )


def test_the_recording_holds_a_known_value_as_a_code_as_no_code_and_counts_it_not(tmp_path):
    """The sink asks of a code what the driver asks (``recorder.wire_code``), whatever the caller
    asked before: here nothing was asked."""
    path = tmp_path / "events.jsonl"
    masker = masking.Masker(known_values=["4711"])
    exchange = {"role": "call", "method": "tools/call", "accepted": None, "http_status": 200}

    with recorder.Recorder.open(path, run_id="r", masker=masker) as held:
        held.token_observation(
            1,
            1,
            kind="no_token",
            exchanges=[{**exchange, "rpc_code": 4711}, {**exchange, "rpc_code": -32001}],
        )

    (observed,) = [e for e in events_of(path) if e["type"] == "token_observation"]
    assert [x["rpc_code"] for x in observed["exchanges"]] == [None, -32001]
    assert masker.replacements["known"] == 0


def test_the_driver_bound_is_the_recorders():
    assert driver.MAX_CODE == events.MAX_RPC_CODE


# -- the opening of the new era --------------------------------------------------------------------


def test_in_the_new_era_discover_is_the_opening_and_there_is_no_era_probe(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), era="modern"), "no_token")

    assert found.roles() == ["opening", "list", "call"]
    assert found.exchanges[0]["method"] == "server/discover"
    assert "era detection" not in found.out


def test_in_the_old_era_discover_is_the_era_probe_once_initialize_follows(serve, drive):
    found = drive(serve(Policy(anonymous_ok=True), era="legacy"), "no_token")

    assert found.roles() == ["era_probe", "opening", "list", "call"]
    assert [x["method"] for x in found.exchanges[:2]] == ["server/discover", "initialize"]
    assert found.out.count("(era detection)") == 1


def test_a_401_on_discover_in_the_new_era_is_the_opening_rejected(serve, drive):
    found = drive(
        serve(Policy(anonymous_ok=True), era="modern", unauthorized_method="server/discover"),
        "no_token",
    )

    assert found.roles() == ["opening"]
    assert (found.exchanges[0]["accepted"], found.exchanges[0]["http_status"]) == (False, 401)
    assert verdict.read(found.path).state == verdict.COMPLETE


# -- a probe module refused at the opening ---------------------------------------------------------

OPENINGS = {"legacy": "initialize", "modern": "server/discover"}


@pytest.mark.parametrize("era", ERAS)
@pytest.mark.parametrize("refused", ["opening", "everything"])
def test_a_probe_run_refused_at_the_opening_says_the_module_was_not_sent(
    era, refused, serve, drive
):
    policy = Policy(anonymous_ok=True) if refused == "opening" else Policy()
    named = {"unauthorized_method": OPENINGS[era]} if refused == "opening" else {}
    found = drive(serve(policy, era=era, **named), "no_token", probe=True)

    assert found.code == 0, found.err
    assert found.exchanges[-1]["role"] == "opening"
    assert found.exchanges[-1]["accepted"] is False
    assert found.skipped == [("probe", "observation_rejected")]
    assert found.of("server_failed") == [] and found.of("step_unanswered") == []
    assert verdict.read(found.path).state == verdict.COMPLETE


@pytest.mark.parametrize("cause", ["http_unreachable", "rate_limited", "no_answer"])
def test_a_probe_run_whose_opening_fails_otherwise_has_no_step_as_without_a_mark(
    cause, serve, drive
):
    """Only a refusal lets the probe's step stand in for the module: any other failure of the
    opening leaves the run as it is without the mark, with no step."""

    def server():
        if cause == "rate_limited":
            return serve(Policy(anonymous_ok=True), statuses=dict.fromkeys(OPENINGS.values(), 429))
        if cause == "no_answer":
            return serve(Policy(anonymous_ok=True), stall="initialize")
        closed = serve(Policy(anonymous_ok=True))
        closed.shutdown()
        closed.server_close()
        return closed

    more = ("--step-timeout", "2")
    found = drive(server(), "no_token", None, *more, probe=True)
    unmarked = drive(server(), None, "tk" + secrets.token_hex(8), *more, probe=True)

    assert found.of("token_observation"), "an observation all the same"
    assert [e["reason"] for e in found.of("server_failed")] == [cause]
    assert found.skipped == unmarked.skipped == []


def test_a_probe_run_without_a_mark_refused_at_the_opening_is_as_it_was(serve, drive):
    found = drive(
        serve(Policy(audience=SERVED)), None, jwt(aud=ELSEWHERE, exp=in_an_hour()), probe=True
    )

    assert found.of("token_observation") == []
    assert found.skipped == []
    assert [e["reason"] for e in found.of("server_failed")] == ["unauthorized"]


# -- a request repeated after Retry-After ----------------------------------------------------------


def test_a_request_repeated_after_retry_after_is_one_entry_with_the_second_answer(
    awkward, drive, monkeypatch
):
    async def sleep(seconds):
        pass

    monkeypatch.setattr(driver, "_sleep", sleep)
    found = drive(
        awkward(Policy(anonymous_ok=True), limit_once={"tools/list": (429, "1")}), "no_token"
    )

    assert found.code == 0, found.err
    (listing,) = found.in_role("list")
    assert (listing["accepted"], listing["http_status"]) == (True, 200)
    (paced,) = found.of("paced")
    assert (paced["why"], paced["status"]) == ("retry_after", 429)


# -- a token in no form in any artifact ------------------------------------------------------------

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"


def forms_of(value: str) -> list[str]:
    """The value as it is, and percent-encoded in either case of the hex digits."""
    encoded = quote(value, safe="")
    return sorted({value, encoded, encoded.lower()})


class Mirrored:
    """Runs as two identities against servers that reflect the token they are sent in every form
    they control, and what is made from them: the store, the report, the bundle."""

    def __init__(
        self,
        root: Path,
        monkey: pytest.MonkeyPatch,
        *,
        crossed: bool = False,
        partial: str | None = None,
    ) -> None:
        self.root = root
        self.captured: list[tuple[str, str, str]] = []
        # A token of digits, which comes back as a JSON number as well as in a string; and a
        # token with the characters that are percent-encoded, which does not. Crossed, the digits
        # are below 2**31, so that the bound of the driver on a code does not hide them from the
        # masker.
        if crossed:
            digits = str(secrets.randbelow(2**31 - 10**9) + 10**9)
        else:
            digits = secrets.choice("123456789") + "".join(
                secrets.choice("0123456789") for _ in range(19)
            )
        plain = f"tk{secrets.token_hex(6)}+{secrets.token_hex(4)}/{secrets.token_hex(3)}="
        self.values = {"digits": digits, "plain": plain}
        for name, value in self.values.items():
            monkey.setenv(f"TEST_MIRROR_{name.upper()}", value)
        # Crossed: the runs are all as ``plain``, and every server hands back the token of
        # ``digits``, which an earlier run sent. A third identity names a variable that is not set.
        # Partial: the other identity has one value that can be read and one that cannot.
        self.crossed = crossed
        self.partial = partial
        self.runs_as = ("plain",) if crossed else tuple(self.values)
        names = [*self.values, *(["ghost"] if crossed else [])]
        monkey.delenv("TEST_MIRROR_GHOST", raising=False)
        monkey.delenv("TEST_MIRROR_HALF_KEY", raising=False)
        identities = [
            {
                "name": name,
                "role": "observation",
                "observation": "foreign_audience",
                "token_env": f"TEST_MIRROR_{name.upper()}",
            }
            for name in names
        ]
        if partial is not None:
            # The token of ``digits`` is the one value that can be read in ``token``: the header
            # names a variable that is not set. In ``header`` it is the other way round.
            half = {"name": "half", "role": "observation", "observation": "foreign_audience"}
            if partial == "token":
                half |= {
                    "token_env": "TEST_MIRROR_DIGITS",
                    "headers": {"X-Half-Key": {"env": "TEST_MIRROR_HALF_KEY"}},
                }
            else:
                half |= {
                    "token_env": "TEST_MIRROR_GHOST",
                    "headers": {"X-Half-Key": {"env": "TEST_MIRROR_DIGITS"}},
                }
            identities = [i for i in identities if i["name"] == "plain"] + [half]
        monkey.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
        self.servers: list = []
        self.held = second_file(
            root / "engagement",
            identities=identities,
            actions={"list": True, "call": True},
            tools=[{"name": "tool_0", "writes": False}],
        )
        script = root / "script.json"
        script.write_text(json.dumps(SCRIPT))
        self.runs = root / "runs"
        self.recordings: dict[str, Path] = {}
        # Each way a server hands a token back: in its answers (in the old and the new era), as a
        # 200 whose error code it is, as a 401 in the middle of the run and as a 403 at the very
        # first request, the body of each holding the token.
        shapes = {
            "accepting": {"policy": Policy()},
            "modern": {"policy": Policy(), "era": "modern"},
            "code": {"policy": Policy(), "code_method": "tools/call"},
            "late": {"policy": Policy(), "unauthorized_method": "tools/call"},
            "denied": {"policy": Policy(audience=SERVED), "deny_status": 403},
        }
        urls = {}
        for shape, behaviour in shapes.items():
            more = {k: v for k, v in behaviour.items() if k != "policy"}
            server = rejecting_server.serve(
                behaviour["policy"],
                mirror=True,
                call_result="text",
                variant="poison",
                echo=digits if crossed else None,
                **more,
            )
            self.servers.append(server)
            urls[shape] = self.url(server)
        # The store takes corpus runs: each server is an entry of a manifest.
        self.manifest = root / "corpus" / "manifest.json"
        self.manifest.parent.mkdir()
        entries = [
            {
                "name": shape,
                "provenance": "poison",
                "source": {"endpoint": url},
                "launch": {"transport": "streamable-http"},
                "scenarios": [os.path.relpath(ALL_SIGNALS, self.manifest.parent)],
            }
            for shape, url in urls.items()
        ]
        self.manifest.write_text(json.dumps({"version": 1, "entries": entries}))
        for who in self.runs_as:
            for shape in shapes:
                name = f"{who}-{shape}"
                code = self.call(
                    "drive", "--manifest", self.manifest, "--entry", shape, "--engagement",
                    self.held, "--out-dir", self.runs / name, "--script", script, "--identity",
                    who,
                )  # fmt: skip
                assert code in (0, 3, 4, 6), (name, code, self.captured[-1][2])
                (self.recordings[name],) = (self.runs / name).glob("*/events.jsonl")
        # Refused: a flag beside an identity, which leaves refusals.jsonl.
        assert self.call(
            "drive", "--manifest", self.manifest, "--entry", "accepting", "--engagement", self.held,
            "--out-dir", self.runs / "refused", "--script", script, "--identity", self.runs_as[0],
            "--token-env", "TEST_MIRROR_DIGITS",
        ) == 2  # fmt: skip
        self.store, self.bundle = root / "store.sqlite", root / "bundle"
        self.report, self.attestation = root / "report.md", root / "attestation.md"
        for step in (
            ("store", "ingest", "--store", self.store, "--engagement", self.held,
             *self.recordings.values()),
            ("report", "--engagement", self.held, "--store", self.store, "--runs", self.runs,
             "--manifest", self.manifest, "--out-dir", self.runs, "--out", self.report),
            ("evidence", "pack", "--engagement", self.held, "--store", self.store,
             "--runs", self.runs, "--manifest", self.manifest, "--report", self.report,
             "--out", self.bundle),
            ("engagement", "attest", "--store", self.store, "--engagement", self.held,
             "--runs", self.runs, "--bundle", self.bundle, "--out", self.attestation),
        ):  # fmt: skip
            code = self.call(*step)
            assert code in (0, 3, 4, 6), (step[:2], code, self.captured[-1][2])

    @staticmethod
    def url(server) -> str:
        return f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"

    def call(self, *argv) -> int:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(part) for part in argv])
        self.captured.append((" ".join(str(p) for p in argv[:2]), out.getvalue(), err.getvalue()))
        return code

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()

    def observed(self, name: str) -> dict:
        (found,) = [e for e in events_of(self.recordings[name]) if e["type"] == "token_observation"]
        return found

    def call_codes(self, name: str) -> list:
        """The ``code`` of each ``call_failed`` of a run: where the ``code`` server puts the
        token, as a number."""
        return [e["code"] for e in events_of(self.recordings[name]) if e["type"] == "call_failed"]

    def artifacts(self) -> list[tuple[str, bytes]]:
        found = [
            (str(path.relative_to(self.root)), path.read_bytes())
            for path in sorted(self.root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        for label, out, err in self.captured:
            found += [(f"stdout of {label}", out.encode()), (f"stderr of {label}", err.encode())]
        return found


@pytest.fixture(scope="module")
def mirrored(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    made = Mirrored(tmp_path_factory.mktemp("token-mirrored"), patch)
    try:
        yield made
    finally:
        made.close()
        patch.undo()


@pytest.fixture(scope="module")
def crossed(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    made = Mirrored(tmp_path_factory.mktemp("token-crossed"), patch, crossed=True)
    try:
        yield made
    finally:
        made.close()
        patch.undo()


@pytest.fixture(scope="module", params=["token", "header"])
def halved(request, tmp_path_factory):
    """Crossed runs whose other identity has a value that can be read and one that cannot."""
    patch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp(f"token-half-{request.param}")
    made = Mirrored(root, patch, crossed=True, partial=request.param)
    try:
        yield made
    finally:
        made.close()
        patch.undo()


def test_the_servers_reflected_the_tokens_and_the_runs_observed_them(mirrored):
    digits = mirrored.values["digits"]
    assert digits.isdigit() and int(digits) > 2**31
    both = {f"Bearer {value}" for value in mirrored.values.values()}
    for server in mirrored.servers:
        assert {s["authorization"] for s in server.behaviour.received} == both
    for name in mirrored.recordings:
        assert mirrored.observed(name)["exchanges"], name
    # The number a server puts where a code goes is not a code when it is the token.
    late = mirrored.observed("digits-late")["exchanges"]
    assert late[-1]["accepted"] is False
    assert late[-1]["rpc_code"] is None
    assert all(x["rpc_code"] != int(digits) for name in mirrored.recordings
               for x in mirrored.observed(name)["exchanges"])  # fmt: skip
    assert mirrored.observed("digits-code")["exchanges"][-1]["rpc_code"] is None
    # The call the server answered with the token as its error code failed, with no code: a
    # token this long is past the bound of a code.
    assert mirrored.call_codes("digits-code") == [None]
    # And where the token is no number, the code is the server's own.
    assert mirrored.observed("plain-late")["exchanges"][-1]["rpc_code"] == -32001
    for name in ("digits-accepting", "digits-modern"):
        text = mirrored.recordings[name].read_text()
        assert masking.PLACEHOLDER in text, "the reflected number is there, as a placeholder"


def test_every_kind_of_artifact_was_made(mirrored):
    artifacts = mirrored.artifacts()
    names = [label for label, _ in artifacts]

    assert sum(n.startswith("runs/") and n.endswith("events.jsonl") for n in names) == 10
    assert any(label.endswith("refusals.jsonl") for label in names)
    for fixed in ("store.sqlite", "report.md", "attestation.md"):
        assert fixed in names
    assert any(label.startswith("bundle/") for label in names)
    assert any(label.startswith("stdout of drive") and content for label, content in artifacts)


def test_no_artifact_holds_a_token_as_digits_in_a_string_or_percent_encoded(mirrored):
    holding = [
        (label, name, form)
        for name, value in mirrored.values.items()
        for form in forms_of(value)
        for label, content in mirrored.artifacts()
        if form.encode() in content
    ]

    assert holding == []


def test_every_view_of_the_web_interface_is_free_of_a_token_in_every_form(mirrored):
    sources = Sources(
        store=mirrored.store,
        runs=mirrored.runs,
        manifests=(mirrored.manifest,),
        scenarios=(ALL_SIGNALS,),
        bundles=(mirrored.bundle,),
        attestations=(mirrored.attestation,),
    )
    shown = every_view(sources, mirrored)

    assert len(shown) > 40
    holding = [
        (name, form)
        for name, text in shown
        for value in mirrored.values.values()
        for form in forms_of(value)
        if form in text
    ]
    assert holding == []


# -- a number in the Masker ------------------------------------------------------------------------

DIGITS = "4" + "".join(secrets.choice("0123456789") for _ in range(17))


def test_a_number_that_holds_a_literal_is_a_placeholder_and_its_path_is_declared():
    masker = masking.Masker(literals=[DIGITS])
    document = {"code": int(DIGITS), "list": [1, -int(DIGITS), 2.5], "ok": True, "n": 42}

    masked, paths = masker.mask_json(document)

    assert masked == {
        "code": masking.PLACEHOLDER,
        "list": [1, masking.PLACEHOLDER, 2.5],
        "ok": True,
        "n": 42,
    }
    assert sorted(paths) == ["code", "list[1]"]


def test_a_number_in_the_http_scrub_is_blanked_as_well():
    masker = masking.Masker(literals=[DIGITS])

    masked, paths = masker._mask_json_http({"data": int(DIGITS)})

    assert masked == {"data": masking.PLACEHOLDER} and paths == ["data"]


def test_a_number_that_holds_no_literal_and_a_bool_are_kept():
    masker = masking.Masker(literals=[DIGITS])
    document = [True, False, 0, 10**40, -32001, 1e300]

    assert masker.mask_json(document) == (document, [])
    assert masking.Masker().mask_json(int(DIGITS)) == (int(DIGITS), [])


# -- the token of another identity ----------------------------------------------------------------


def test_the_servers_gave_back_the_token_of_digits_to_runs_that_sent_plain(crossed):
    digits, plain = crossed.values["digits"], crossed.values["plain"]
    assert len(digits) == 10 and digits.isdigit() and 10**9 <= int(digits) < 2**31
    for server in crossed.servers:
        # Only the chosen identity is sent: the token of ``digits`` goes nowhere.
        assert {s["authorization"] for s in server.behaviour.received} == {f"Bearer {plain}"}
    assert sorted(crossed.recordings) == sorted(f"plain-{shape}" for shape in (
        "accepting", "modern", "code", "late", "denied"))  # fmt: skip
    for name in ("plain-accepting", "plain-modern"):
        text = crossed.recordings[name].read_text()
        assert masking.PLACEHOLDER in text, "the token of digits is there, as a placeholder"
    assert crossed.observed("plain-code")["exchanges"][-1]["rpc_code"] is None
    assert crossed.observed("plain-late")["exchanges"][-1]["rpc_code"] is None
    # Within the bound of a code, the token of another identity is no code in call_failed either:
    # the recorder knows it as a literal of the run.
    assert crossed.call_codes("plain-code") == [None]


def test_every_kind_of_artifact_was_made_in_the_crossed_runs(crossed):
    names = [label for label, _ in crossed.artifacts()]

    assert sum(n.startswith("runs/") and n.endswith("events.jsonl") for n in names) == 5
    assert any(label.endswith("refusals.jsonl") for label in names)
    for fixed in ("store.sqlite", "report.md", "attestation.md"):
        assert fixed in names
    assert any(label.startswith("bundle/") for label in names)


def test_no_artifact_holds_the_token_of_another_identity_in_any_form(crossed):
    holding = [
        (label, form)
        for form in forms_of(crossed.values["digits"])
        for label, content in crossed.artifacts()
        if form.encode() in content
    ]
    assert holding == []


def test_no_view_of_the_web_interface_holds_the_token_of_another_identity(crossed):
    sources = Sources(
        store=crossed.store,
        runs=crossed.runs,
        manifests=(crossed.manifest,),
        scenarios=(ALL_SIGNALS,),
        bundles=(crossed.bundle,),
        attestations=(crossed.attestation,),
    )
    shown = every_view(sources, crossed)

    assert len(shown) > 40
    assert [
        (name, form)
        for name, text in shown
        for form in forms_of(crossed.values["digits"])
        if form in text
    ] == []


def test_an_identity_that_cannot_be_read_does_not_stop_the_run_and_is_not_named(crossed):
    # The third identity, ``ghost``, names a variable that is not set: the runs went on.
    assert all(crossed.observed(name)["exchanges"] for name in crossed.recordings)
    said = "".join(out + err for _, out, err in crossed.captured)
    assert "ghost" not in said and "TEST_MIRROR_GHOST" not in said


def test_the_value_that_can_be_read_of_another_identity_is_a_literal_by_itself(halved):
    digits = halved.values["digits"]
    assert 10**9 <= int(digits) < 2**31
    for server in halved.servers:
        # Neither the token nor the header of the other identity is sent.
        assert {s["authorization"] for s in server.behaviour.received} == {
            f"Bearer {halved.values['plain']}"
        }
    for name in ("plain-accepting", "plain-modern"):
        text = halved.recordings[name].read_text()
        assert masking.PLACEHOLDER in text, "the value is there, as a placeholder"
    assert halved.observed("plain-code")["exchanges"][-1]["rpc_code"] is None
    assert halved.call_codes("plain-code") == [None]
    assert all(halved.observed(name)["exchanges"] for name in halved.recordings)
    assert halved.artifacts() and not [
        (label, form)
        for form in forms_of(digits)
        for label, content in halved.artifacts()
        if form.encode() in content
    ]
    # The value that could not be read is passed by without a word: neither its variable nor the
    # identity is named.
    said = "".join(out + err for _, out, err in halved.captured)
    assert "TEST_MIRROR_HALF_KEY" not in said and "TEST_MIRROR_GHOST" not in said
    assert "identity half" not in said and "X-Half-Key" not in said


def test_no_view_of_the_web_interface_holds_the_value_of_a_half_readable_identity(halved):
    sources = Sources(
        store=halved.store,
        runs=halved.runs,
        manifests=(halved.manifest,),
        scenarios=(ALL_SIGNALS,),
        bundles=(halved.bundle,),
        attestations=(halved.attestation,),
    )
    shown = every_view(sources, halved)

    assert len(shown) > 40
    assert [
        (name, form)
        for name, text in shown
        for form in forms_of(halved.values["digits"])
        if form in text
    ] == []


def others_of(held: Path, chosen: str = "reader") -> list[str]:
    """``cli.other_credentials`` for a run as ``chosen``, in a thread that may not wait: a read
    that waits for a writer fails the test."""
    loaded = engagement.load(held)
    args = type("Args", (), {"identity": chosen})()
    found: list[list[str]] = []
    reader = threading.Thread(target=lambda: found.append(cli.other_credentials(args, loaded)))
    reader.daemon = True
    reader.start()
    reader.join(5)
    assert not reader.is_alive(), "the read of another identity's token_file waited"
    return found[0]


def test_the_token_file_of_another_identity_is_read_under_the_same_checks(tmp_path):
    # A value that can be read: it is a literal.
    value = "tf" + secrets.token_hex(12)
    held = token_file_engagement(tmp_path / "plain", "token")
    (held.parent / "token").write_text(value + "\n")
    assert others_of(held) == [value]

    # A FIFO is no regular file: passed by, and the open does not wait for a writer.
    held = token_file_engagement(tmp_path / "fifo", "fifo")
    os.mkfifo(held.parent / "fifo")
    assert others_of(held) == []

    # A link that points out of the directory once the file was loaded is not followed.
    outside = tmp_path / ("elsewhere-" + secrets.token_hex(4))
    outside.write_text("tf" + secrets.token_hex(12) + "\n")
    held = token_file_engagement(tmp_path / "link", "token")
    (held.parent / "token").write_text(value + "\n")
    loaded = engagement.load(held)
    (held.parent / "token").unlink()
    (held.parent / "token").symlink_to(outside)
    args = type("Args", (), {"identity": "reader"})()
    assert cli.other_credentials(args, loaded) == []


def test_the_chosen_identity_must_be_readable(tmp_path, serve, monkeypatch):
    monkeypatch.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    held = second_file(tmp_path / "engagement", identities=[identity("foreign_audience")])
    server = serve(Policy(anonymous_ok=True))
    url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(
            ["drive", "--engagement", str(held), "--out-dir", str(tmp_path / "runs"),
             "--http", url, "--identity", "observer"]
        )  # fmt: skip

    assert code == 2
    assert server.behaviour.received == []


# -- the secret headers of the chosen identity, and the claims of its token -----------------------

KEY_ENV = "TEST_KEY_OBSERVED"
SECRET_ENV = "TEST_SECRET_OBSERVED"  # noqa: S105 - the name of a variable


def traces_of(value: str) -> list[str]:
    """A secret value in every form a scan looks for: as it is, percent-encoded (in either case
    of the hex digits, and with ``/`` left standing), and in pieces: each part between ``+``,
    ``/`` and ``=`` of 12 characters or more, and every run of 16 characters inside one."""
    parts = [part for part in re.split(r"[+/=]", value) if len(part) >= 12]
    return sorted({*forms_of(value), quote(value, safe="/"), *pieces(parts, value)})


def cli_run(*argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main([str(part) for part in argv])
    return code, out.getvalue(), err.getvalue()


def test_a_secret_header_and_a_claim_of_the_chosen_identity_are_in_no_artifact(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
    # Digits below 2**31, so that the bound on a code does not hide them from the masker; and a
    # value with the characters that are percent-encoded.
    key = str(secrets.randbelow(2**31 - 10**9) + 10**9)
    secret = f"hs{secrets.token_hex(10)}+{secrets.token_hex(8)}/{secrets.token_hex(4)}="
    audience = "aud-" + secrets.token_hex(8)
    monkeypatch.setenv(TOKEN_ENV, jwt(aud=audience, exp=in_an_hour()))
    monkeypatch.setenv(KEY_ENV, key)
    monkeypatch.setenv(SECRET_ENV, secret)
    chosen = {
        **identity("foreign_audience"),
        "headers": {"X-Api-Key": {"env": KEY_ENV}, "X-Secret": {"env": SECRET_ENV}},
    }
    held = second_file(
        tmp_path / "engagement",
        identities=[chosen],
        actions={"list": True, "call": True},
        tools=[{"name": "tool_0", "writes": False}],
    )
    script = tmp_path / "script.json"
    script.write_text(json.dumps(SCRIPT))
    # A server mirrors one of the headers back in every form it controls: in its answers (in the
    # old and the new era), as the code of a 200 error to the call, in the body of a 401 to the
    # call and of a 403 at the first request. One more writes every header back into the names
    # of what it lists, so that the call is not sent.
    shapes = {
        "accepting": (Policy(), {}),
        "modern": (Policy(), {"era": "modern"}),
        "code": (Policy(), {"code_method": "tools/call"}),
        "late": (Policy(), {"unauthorized_method": "tools/call"}),
        "denied": (Policy(audience=SERVED), {"deny_status": 403}),
    }
    runs = {
        f"{header}-{shape}": (policy, {"mirror": True, "mirror_header": header, **behaviour})
        for header in ("X-Api-Key", "X-Secret")
        for shape, (policy, behaviour) in shapes.items()
    }
    runs["reflected"] = (Policy(), {"reflect": ("X-Api-Key", "X-Secret", "Authorization")})
    said: list[tuple[str, str]] = []
    observed: dict[str, dict] = {}
    servers = []
    try:
        for name, (policy, behaviour) in runs.items():
            server = rejecting_server.serve(policy, call_result="text", **behaviour)
            servers.append(server)
            url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
            code, out, err = cli_run(
                "drive", "--engagement", held, "--out-dir", tmp_path / "runs" / name,
                "--script", script, "--http", url, "--identity", "observer",
            )  # fmt: skip
            # Incomplete where the call was not sent; call_failed where it was answered an error.
            expected = 3 if name == "reflected" else 6 if name.endswith("-code") else 0
            assert code == expected, (name, err)
            said += [(f"{name}.stdout", out), (f"{name}.stderr", err)]
            (path,) = (tmp_path / "runs" / name).glob("*/events.jsonl")
            (observed[name],) = [e for e in events_of(path) if e["type"] == "token_observation"]
            # The server did hand the header back: a mirror that sends nothing proves nothing.
            if name == "reflected":
                received = server.behaviour.received[0]
                assert (received.get("x-api-key"), received.get("x-secret")) == (key, secret)
                # The names it lists carry the values: the call's tool is not among them.
                (finished,) = [e for e in events_of(path) if e["type"] == "script_finished"]
                assert ["tools/call", "tool_not_listed"] in finished["skipped"]
            else:
                value = key if name.startswith("X-Api-Key") else secret
                assert ("text", value) in server.behaviour.mirrored, name
                if name == "X-Api-Key-code":
                    assert ("number", key) in server.behaviour.mirrored
        # Refused at the gate, a flag beside an identity: refusals.jsonl.
        code, out, err = cli_run(
            "drive", "--engagement", held, "--out-dir", tmp_path / "refused", "--script", script,
            "--http", url, "--identity", "observer", "--token-env", TOKEN_ENV,
        )  # fmt: skip
        assert code == 2
        said += [("refused.stdout", out), ("refused.stderr", err)]
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()

    # The code of the 200 error is the key: no code, since it is a value of the run.
    (call,) = [x for x in observed["X-Api-Key-code"]["exchanges"] if x["role"] == "call"]
    assert (call["accepted"], call["http_status"], call["rpc_code"]) == (None, 200, None)
    (late,) = [x for x in observed["X-Api-Key-late"]["exchanges"] if x["role"] == "call"]
    assert (late["accepted"], late["rpc_code"]) == (False, None)
    for header in ("X-Api-Key", "X-Secret"):
        assert [x["accepted"] for x in observed[f"{header}-denied"]["exchanges"]] == [False]
    artifacts = [(str(path), path.read_bytes()) for path in sorted(tmp_path.rglob("*"))
                 if path.is_file()]  # fmt: skip
    artifacts += [(label, text.encode()) for label, text in said]
    assert any(label.endswith("refusals.jsonl") for label, _ in artifacts)
    assert len([label for label, _ in artifacts if label.endswith("events.jsonl")]) == len(runs)
    assert [
        (label, form)
        for value in (key, secret)
        for form in traces_of(value)
        for label, content in artifacts
        if form.encode() in content
    ] == []
    # A claim of the token is in no token_observation and on no stdout.
    assert [shape for shape, event in observed.items() if audience in json.dumps(event)] == []
    assert [label for label, text in said if label.endswith(".stdout") and audience in text] == []


@pytest.mark.parametrize("unreadable", ["fifo", "link"])
def test_an_unreadable_token_file_of_another_identity_is_passed_by_without_a_word(
    unreadable, tmp_path, serve, monkeypatch
):
    monkeypatch.setenv(SALT_ENV, "salt-" + secrets.token_hex(16))
    monkeypatch.setenv(TOKEN_ENV, jwt(aud=ELSEWHERE, exp=in_an_hour()))
    other = "filed" + secrets.token_hex(3)
    filename = "tf" + secrets.token_hex(4)
    held = second_file(
        tmp_path / "engagement",
        identities=[
            identity("foreign_audience"),
            {"name": other, "role": "observation", "token_file": filename},
        ],
        actions={"list": True, "call": True},
        tools=[{"name": "tool_0", "writes": False}],
    )
    filed = held.parent / filename
    outside = tmp_path / ("elsewhere" + secrets.token_hex(4))
    hidden = "tf" + secrets.token_hex(12)
    outside.write_text(hidden + "\n")
    if unreadable == "fifo":
        os.mkfifo(filed)
    else:
        filed.write_text("tf" + secrets.token_hex(12) + "\n")
    original = cli.other_credentials
    asked = []

    def swapped(args, loaded):
        # The file was loaded as a regular file in the directory; by the time it is read for the
        # masker it is a link that points out of it.
        if unreadable == "link":
            filed.unlink()
            filed.symlink_to(outside)
        asked.append(loaded)
        return original(args, loaded)

    monkeypatch.setattr(cli, "other_credentials", swapped)
    script = tmp_path / "script.json"
    script.write_text(json.dumps(SCRIPT))
    server = serve(Policy(anonymous_ok=True))
    url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
    code, out, err = cli_run(
        "drive", "--engagement", held, "--out-dir", tmp_path / "runs", "--script", script,
        "--http", url, "--identity", "observer",
    )  # fmt: skip

    assert code == 0, err
    assert asked, "the identities of the file were not read for the masker"
    assert filed.is_symlink() == (unreadable == "link")
    for word in (other, filename, str(filed), outside.name, hidden):
        assert word not in out and word not in err
    (path,) = (tmp_path / "runs").glob("*/events.jsonl")
    assert hidden not in path.read_text()


# -- a token that is a number, in a run through the CLI -------------------------------------------


# Every way a refusal's body can go, but the long stall, which only takes longer than ``stall``.
@pytest.mark.parametrize(
    "rejection", [None, *sorted(set(rejecting_server.REJECTIONS) - {"long_stall"})]
)
def test_the_mirror_notes_only_what_it_sent_of_a_refusal(rejection, awkward, drive):
    # The fixture's own account, which the scans rely on: the X-Echo header at the head of the
    # refusal went out, the body holds the token only where it is the whole JSON-RPC error.
    token = secrets.choice("123456789") + "".join(secrets.choice("0123456789") for _ in range(8))
    server = awkward(Policy(audience=SERVED), mirror=True, rejection=rejection)
    drive(server, "foreign_audience", token)

    expected = [("text", token)]
    if rejection is None:
        expected += [("text", token), ("number", token)]
    assert server.behaviour.mirrored == expected


# What the mirror notes of an answer is what its written bytes hold, in order: the X-Echo header
# with the head, then the text of the body and the number of the body where they went out. A
# result that is no object holds nothing of the token; half of a listing holds nothing of it (the
# echo is at the end of the result); a body without its last character holds all of it; a body
# cut after ``seen<token>`` holds the text, and not yet the number, which comes after it.
HEADER, BODY_TEXT, BODY_NUMBER = ["text"], ["text"], ["number"]
ANSWERS = {
    "string-result": ({"call_result": "string-result"}, "tools/call", HEADER),
    "no-result": ({"call_result": "no-result"}, "tools/call", HEADER),
    "text": ({"call_result": "text"}, "tools/call", HEADER + BODY_TEXT + BODY_NUMBER),
    "missing-end": ({"failure": "missing-end"}, "tools/list", HEADER + BODY_TEXT + BODY_NUMBER),
    "aborted-stream": ({"failure": "aborted-stream"}, "tools/list", HEADER),
    "cut-after-text": (
        {"call_result": "text", "cut_method": "tools/call"},
        "tools/call",
        HEADER + BODY_TEXT,
    ),
}


@pytest.mark.parametrize("case", sorted(ANSWERS))
def test_the_mirror_notes_of_an_answer_what_its_bytes_held(case, drive):
    behaviour, method, forms = ANSWERS[case]
    token = secrets.choice("123456789") + "".join(secrets.choice("0123456789") for _ in range(8))
    server = rejecting_server.serve(Policy(), mirror=True, **behaviour)
    try:
        drive(server, "foreign_audience", token)
    finally:
        server.shutdown()
        server.server_close()

    # The method is answered once in each case.
    assert server.behaviour.mirrored_by_method[method] == [(form, token) for form in forms]


def test_a_code_that_is_the_token_of_the_run_is_not_recorded_as_a_code(awkward, drive, tmp_path):
    token = secrets.choice("123456789") + "".join(secrets.choice("0123456789") for _ in range(8))
    assert 0 < int(token) < 2**31
    server = awkward(Policy(audience=SERVED), mirror=True)
    found = drive(server, "foreign_audience", token)

    # The body of the 401 holds the token as error.code: the server did send it.
    assert server.behaviour.received[0]["authorization"] == f"Bearer {token}"
    (exchange,) = found.exchanges
    assert (exchange["accepted"], exchange["http_status"], exchange["rpc_code"]) == (
        False, 401, None,
    )  # fmt: skip
    assert "rejected\tstatus 401\tcode -\n" in found.out
    artifacts = [path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()]
    artifacts += [found.out.encode(), found.err.encode()]
    assert [a for a in artifacts if token.encode() in a] == []
