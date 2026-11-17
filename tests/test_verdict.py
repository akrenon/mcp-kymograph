"""What a driven run is worth, and the exit code that says so — one code per state.

A batch decides from the exit code whether a run is usable. So the four outcomes that used to
share a code are kept apart here, each by its own test: the sandbox did not hold (5), the
server never answered (4), data is missing (3), and — not a state at all — a server that ended
with some code of its own, which in driver mode is recorded and never handed through.
"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, fleet, verdict
from mcp_kymograph.events import SCHEMA_VERSION
from mcp_kymograph.sandbox import docker
from mcp_kymograph.store import Store
from test_store import recording

FIXTURES = Path(__file__).parent / "fixtures"
SERVER = FIXTURES / "discovery_server.py"
PROJECT = FIXTURES / "corpus" / "manifest.yaml"


# -- the judgement, on events ---------------------------------------------------------------


def started(**extra):
    return {"type": "run_started", "mode": "driver", "isolation": "host", **extra}


#: What a server that answered, and a client that spoke, leave in the closing event.
SPOKE = {"server_output_bytes": 100, "client_input_bytes": 100, "server_exited_first": False}


def finished(counts=None, **extra):
    return {"type": "run_finished", "findings_by_statement": counts or {}, **SPOKE, **extra}


#: The driver's evidence that its script reached its end.
ENDED = {"type": "script_finished", "inventory": "complete"}


def test_a_run_with_nothing_wrong_is_complete_and_exits_zero():
    judged = verdict.assess([started(), ENDED, finished()])
    assert judged.state == verdict.COMPLETE
    assert judged.exit_code == 0
    assert judged.problems == []


@pytest.mark.parametrize(
    ("events", "state", "fragment"),
    [
        ([started(), {"type": "server_failed", "reason": "no_answer"}, finished()],
         verdict.SERVER_FAILED, "server_failed: no_answer"),
        ([started(), {"type": "sandbox_failed", "condition": "probe", "phase": "before_target"},
          finished()], verdict.SANDBOX_FAILED, "sandbox_failed: probe (before_target)"),
        ([started(isolation="runc"), {"type": "egress_summary", "consistent": False}, finished()],
         verdict.SANDBOX_FAILED, "the sink's account differs"),
        ([started(isolation="runc"), finished()], verdict.INCOMPLETE, "without egress_summary"),
        ([started()], verdict.INCOMPLETE, "no run_finished"),
        ([started(), finished(inspection_bounded=1)], verdict.INCOMPLETE, "partly inspected"),
        ([started(), finished({"st": {"imperative": 2}})], verdict.INCOMPLETE,
         "2 made, 0 recorded"),
        ([finished()], verdict.INCOMPLETE, "does not begin with run_started"),
    ],
)  # fmt: skip
def test_each_shortfall_has_its_state_and_its_reason(events, state, fragment):
    judged = verdict.assess(events)
    assert judged.state == state
    assert judged.exit_code == verdict.EXIT_CODES[state]
    assert any(fragment in problem for problem in judged.problems), judged.problems


# -- what the sink missed of the target's UDP -------------------------------------------------


def runc_run(loss):
    summary = {"type": "egress_summary", "consistent": True}
    if loss is not None:
        summary["udp_loss"] = loss
    return [started(isolation="runc"), summary, ENDED, finished()]


@pytest.mark.parametrize(
    "loss",
    [
        {"kernel": 5000, "sink": 5000, "lost": 0, "unseen_destinations": 0, "rate": 0.0},
        {"kernel": 0, "sink": 0, "lost": 0, "unseen_destinations": 0, "rate": 0.0},
    ],
)
def test_a_sandboxed_run_whose_sink_missed_nothing_is_complete(loss):
    """At the limit: every datagram the kernel counted, the sink received."""
    judged = verdict.assess(runc_run(loss))
    assert judged.state == verdict.COMPLETE, judged.problems


def test_a_sandboxed_run_whose_sink_missed_one_datagram_is_incomplete():
    """Just past the limit: one of 5000, at a destination the sink saw otherwise. What that
    datagram carried was not observed, and a target can aim at exactly one."""
    loss = {"kernel": 5000, "sink": 4999, "lost": 1, "unseen_destinations": 0, "rate": 0.0002}
    judged = verdict.assess(runc_run(loss))
    assert judged.state == verdict.INCOMPLETE
    assert judged.problems == [
        "the sink missed 1 of 5000 UDP datagram(s) (0.02%): what they carried was not observed"
    ]


LOSSY = {"kernel": 5000, "sink": 4999, "lost": 1, "unseen_destinations": 0}
UNANSWERED = {"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": "no_answer"}
UNDECODABLE = {
    "type": "message",
    "direction": "server_to_client",
    "parse": {"ok": False, "error_reason": "not_utf8"},
}


@pytest.mark.parametrize(
    ("events", "cause"),
    [
        (runc_run(LOSSY), "udp_loss"),
        (runc_run(None), "udp_loss_unknown"),
        ([started(), UNANSWERED, ENDED, finished()], "step_unanswered"),
        ([started(), ENDED, finished(inspection_bounded=1)], "inspection_bounded"),
        ([started(), UNDECODABLE, ENDED, finished()], "message_undecodable"),
        ([started(), ENDED, finished({"st": {"imperative": 2}})], "findings_missing"),
        ([started(), finished()], "no_script_finished"),
        ([started(), ENDED], "no_run_finished"),
        ([started(isolation="runc"), ENDED, finished()], "no_egress_summary"),
        ([started(), {"type": "server_failed", "reason": "no_answer"}, ENDED, finished()],
         "server_failed"),
        ([started(), {"type": "sandbox_failed", "condition": "probe", "phase": "before_target"},
          ENDED, finished()], "sandbox_failed"),
        ([started(), {"type": "sandbox_failed", "condition": "record", "phase": "after_target"},
          ENDED, finished()], "sandbox_failed_after_target"),
    ],
)  # fmt: skip
def test_each_kind_of_shortfall_carries_its_own_cause(events, cause):
    """A run incomplete because the sink missed datagrams is told apart from one incomplete for
    any other reason by a key, not by reading its words."""
    judged = verdict.assess(events)
    assert judged.causes == [cause], judged.problems
    assert cause in verdict.CAUSES


def test_a_run_short_in_two_ways_names_both_causes_and_no_cause_is_made_up():
    judged = verdict.assess(runc_run(LOSSY)[:2] + [UNANSWERED, ENDED, finished()])
    assert judged.causes == ["step_unanswered", "udp_loss"]
    with pytest.raises(ValueError, match="not a cause"):
        verdict.Verdict().add(verdict.INCOMPLETE, "something", cause="something")


def test_a_destination_the_sink_never_saw_is_named_in_the_reason():
    loss = {"kernel": 3, "sink": 2, "lost": 1, "unseen_destinations": 1}
    (problem,) = verdict.assess(runc_run(loss)).problems
    assert "1 destination(s) not once" in problem


def test_the_rate_is_worked_out_from_the_counts_not_read_from_the_file():
    loss = {"kernel": 10, "sink": 7, "lost": 3, "unseen_destinations": 0, "rate": 0.0}
    assert verdict.assess(runc_run(loss)).state == verdict.INCOMPLETE


@pytest.mark.parametrize(
    "loss",
    [None, [], {"kernel": 10}, {"kernel": 10, "lost": -1}, {"kernel": True, "lost": 0},
     {"kernel": "10", "lost": 0}, {"kernel": 2, "lost": 3}],
)  # fmt: skip
def test_a_sandboxed_run_without_a_readable_loss_account_is_incomplete(loss):
    judged = verdict.assess(runc_run(loss))
    assert judged.state == verdict.INCOMPLETE
    assert any("udp_loss" in p for p in judged.problems), judged.problems


def test_the_gravest_shortfall_decides_the_state():
    """A sandbox that did not hold explains a server that never answered, which explains the
    data that is missing — never the other way round."""
    events = [
        started(),
        {"type": "server_failed", "reason": "no_answer"},
        {"type": "sandbox_failed", "condition": "images", "phase": "before_target"},
    ]
    judged = verdict.assess(events)
    assert {s.state for s in judged.shortfalls} == {
        verdict.SANDBOX_FAILED,
        verdict.SERVER_FAILED,
        verdict.INCOMPLETE,
    }
    assert judged.state == verdict.SANDBOX_FAILED
    assert verdict.gravest([verdict.INCOMPLETE, verdict.SERVER_FAILED]) == verdict.SERVER_FAILED
    assert verdict.gravest([]) == verdict.COMPLETE


def test_the_five_states_have_five_codes_none_of_them_success_and_none_the_refusal():
    codes = [verdict.EXIT_CODES[state] for state in verdict.STATES]
    assert len(set(codes)) == 5
    assert verdict.EXIT_CODES[verdict.COMPLETE] == 0
    assert cli.EXIT_REFUSED not in codes


def test_the_server_s_own_exit_is_carried_and_is_no_shortfall():
    judged = verdict.assess(
        [started(), ENDED, {"type": "server_exited", "exit_code": 3}, finished()]
    )
    assert judged.server_exit == {"exit_code": 3, "signal": None}
    assert judged.state == verdict.COMPLETE


def test_a_recording_that_cannot_be_read_is_incomplete(tmp_path):
    judged = verdict.read(tmp_path / "missing.jsonl")
    assert judged.state == verdict.INCOMPLETE


# -- one exit code per state, end to end ----------------------------------------------------


def drive(tmp_path, *server_args, extra=()):
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), *extra, "--", sys.executable, str(SERVER),
         *server_args]
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


def drive_entry(tmp_path, *flags):
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), "--manifest", str(PROJECT), "--entry",
         "poison-server", *flags]
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return code, path


def test_a_sandbox_that_cannot_be_built_exits_with_its_own_code(tmp_path, monkeypatch):
    """No Docker here at all: the sandbox fails at its first step, the server never starts,
    and the run says sandbox_failed — 5, not 3 and not the server's code."""
    monkeypatch.setattr(docker, "DOCKER", str(tmp_path / "no-docker-here"))
    code, path = drive_entry(tmp_path, "--isolation", "runc")
    assert code == cli.EXIT_SANDBOX_FAILED == 5
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert [e["condition"] for e in events if e["type"] == "sandbox_failed"] == ["images"]
    assert not [e for e in events if e["type"] == "server_exited"]
    with Store.open(tmp_path / "store.sqlite") as store:
        assert store.ingest(path).state == verdict.SANDBOX_FAILED


@pytest.mark.parametrize("server_args", [("--fail-initialize",), ("--silent",)])
def test_a_server_that_never_completes_the_handshake_exits_with_its_own_code(tmp_path, server_args):
    code, path, _ = drive(tmp_path, *server_args, extra=("--step-timeout", "2.0"))
    assert code == cli.EXIT_SERVER_FAILED == 4
    assert verdict.read(path).state == verdict.SERVER_FAILED


def test_a_run_that_lacks_data_exits_incomplete(tmp_path, capsys):
    """2100 tools in one listing: more strings than one message is inspected over, so the
    message is only partly looked at — missing data, 3, said on the terminal."""
    code, path, events = drive(tmp_path, "--tool-count", "2100")
    assert code == cli.EXIT_INCOMPLETE == 3
    assert events[-1]["inspection_bounded"] == 1
    assert verdict.read(path).state == verdict.INCOMPLETE
    assert "incomplete [inspection_bounded] (" in capsys.readouterr().err


@pytest.mark.parametrize("own", [3, 4, 5, 1])
def test_a_server_s_own_exit_code_is_recorded_and_never_handed_through(tmp_path, capsys, own):
    """The server ends with exactly the codes the states use. The run itself is complete:
    the exit is 0, the server's code is in the recording, and the terminal says so."""
    code, path, events = drive(tmp_path, "--exit-code", str(own))
    assert code == 0
    assert [e["exit_code"] for e in events if e["type"] == "server_exited"] == [own]
    assert verdict.read(path).server_exit == {"exit_code": own, "signal": None}
    assert f"the server ended with exit code {own}; recorded, not handed through" in (
        capsys.readouterr().err
    )


def test_ingesting_exits_with_the_gravest_state_filed(tmp_path, monkeypatch):
    """One complete run and one whose sandbox failed: the store files both, each in its state,
    and the exit says the graver one."""
    good_code, good = drive_entry(tmp_path / "good")
    assert good_code == 0
    monkeypatch.setattr(docker, "DOCKER", str(tmp_path / "no-docker-here"))
    bad_code, bad = drive_entry(tmp_path / "bad", "--isolation", "runc")
    assert bad_code == cli.EXIT_SANDBOX_FAILED
    database = str(tmp_path / "store.sqlite")
    assert cli.main(["store", "ingest", "-q", "--store", database, str(good)]) == 0
    assert cli.main(["store", "ingest", "-q", "--store", database, str(good), str(bad)]) == 5
    with Store.open(database) as store:
        states = sorted(run.state for run in store.runs())
    assert states == [verdict.COMPLETE, verdict.SANDBOX_FAILED]


@pytest.mark.parametrize(
    ("sandbox", "server", "code"),
    [("probe", None, verdict.EXIT_SANDBOX_FAILED), (None, "no_answer", verdict.EXIT_SERVER_FAILED)],
)
def test_what_the_process_saw_counts_even_when_the_recording_lacks_it(
    tmp_path, sandbox, server, code
):
    """The exit code is the recording's state — plus what this process saw itself. A failure
    whose event never reached the disk must still not leave a complete run behind."""
    from types import SimpleNamespace

    path = tmp_path / "events.jsonl"
    events = [started(schema_version=SCHEMA_VERSION), ENDED, finished()]
    path.write_text("".join(json.dumps({"v": SCHEMA_VERSION, **e}) + "\n" for e in events))
    assert verdict.read(path).state == verdict.COMPLETE  # the recording alone says complete
    view = cli.TerminalView(sys.stderr, quiet=True)
    outcome = SimpleNamespace(sandbox_failed=sandbox)
    assert cli._driven_exit(view, path, outcome, server) == code


@pytest.mark.parametrize(
    "outcome",
    [{"server_failed": "not_started", "server_silent": False},
     {"server_failed": None, "server_silent": True}],
)  # fmt: skip
def test_a_server_the_process_saw_fail_counts_even_when_the_recording_lacks_it(tmp_path, outcome):
    """Not started, or silent: seen by the process itself, and server_failed even if the
    recording that says so never reached the disk."""
    from types import SimpleNamespace

    path = tmp_path / "events.jsonl"
    events = [started(schema_version=SCHEMA_VERSION), ENDED, finished()]
    path.write_text("".join(json.dumps({"v": SCHEMA_VERSION, **e}) + "\n" for e in events))
    assert verdict.read(path).state == verdict.COMPLETE
    view = cli.TerminalView(sys.stderr, quiet=True)
    seen = SimpleNamespace(sandbox_failed=None, **outcome)
    assert cli._driven_exit(view, path, seen, None) == verdict.EXIT_SERVER_FAILED


# -- proxy mode: the server's code is handed through, the state is in the recording ---------


INITIALIZE = (
    json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "0"}},
        }
    ).encode()
    + b"\n"
)  # fmt: skip


def proxy(tmp_path, *server_args):
    out = tmp_path / "runs"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "run", "-q", "--out-dir", str(out), "--",
         sys.executable, str(SERVER), *server_args],
        input=INITIALIZE, capture_output=True, timeout=60, check=False,
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return done, path, [json.loads(line) for line in path.read_text().splitlines()]


def read_back(path):
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "verdict", "-q", str(path)],
        capture_output=True, timeout=60, check=False,
    )  # fmt: skip
    return done.returncode, json.loads(done.stdout)


@pytest.mark.parametrize("own", [4, 3, 5])
def test_a_server_ending_with_4_in_proxy_mode_is_handed_through_and_not_read_as_server_failed(
    tmp_path, own
):
    """The client sees the server's own 4 — and that is all the 4 is. The server answered the
    handshake; nothing in the recording says server_failed, and the run read back from it is
    complete. The terminal says whose code it was and where the state is."""
    done, path, events = proxy(tmp_path, "--exit-code", str(own))
    assert done.returncode == own
    assert [e["exit_code"] for e in events if e["type"] == "server_exited"] == [own]
    assert not [e for e in events if e["type"] in ("server_failed", "sandbox_failed")]
    judged = verdict.read(path)
    assert judged.state == verdict.COMPLETE, judged.problems
    assert verdict.SERVER_FAILED not in {s.state for s in judged.shortfalls}
    assert judged.server_exit == {"exit_code": own, "signal": None}
    assert (
        f"exit code {own} is the server's own, handed through, not this run's state; that is "
        f"in the recording: kymograph verdict {path}"
    ) in done.stderr.decode()
    assert read_back(path) == (
        0,
        {"recording": str(path), "state": "complete", "exit_code": 0,
         "rules": verdict.RULES_VERSION, "causes": [], "problems": [],
         "server_exit": {"exit_code": own, "signal": None}, "truncations": [],
         "isolation": "host", "egress_observed": False},
    )  # fmt: skip


def test_a_server_code_that_is_none_of_ours_is_handed_through_without_a_word(tmp_path):
    done, _, _ = proxy(tmp_path, "--exit-code", "1")
    assert done.returncode == 1
    assert b"handed through" not in done.stderr


def test_the_verdict_command_reads_the_state_a_driven_run_exited_with(tmp_path):
    """The same state from the recording that drive exited with: 4 for a server that never
    answered, the run's directory as good as its events file."""
    code, path, _ = drive(tmp_path, "--fail-initialize", extra=("--step-timeout", "2.0"))
    assert code == verdict.EXIT_SERVER_FAILED
    read_code, judged = read_back(path.parent)
    assert (read_code, judged["state"]) == (verdict.EXIT_SERVER_FAILED, verdict.SERVER_FAILED)
    assert judged["recording"] == str(path)


def test_the_verdict_command_on_a_recording_that_cannot_be_read_says_incomplete(tmp_path):
    read_code, judged = read_back(tmp_path / "nothing-here.jsonl")
    assert (read_code, judged["state"]) == (verdict.EXIT_INCOMPLETE, verdict.INCOMPLETE)
    assert "cannot be read" in judged["problems"][0]


@pytest.mark.parametrize(
    ("command", "says"),
    [("run", "indistinguishable by exit status"), ("drive", "never handed through")],
)
def test_each_mode_s_help_says_whose_exit_status_it_is(command, says):
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", command, "--help"],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert says in " ".join(done.stdout.split())
    assert "kymograph verdict" in " ".join(done.stdout.split()) or command == "drive"


@pytest.mark.parametrize(
    ("phase", "cause"),
    [
        ({"phase": "before_target"}, "sandbox_failed"),
        ({"phase": "after_target"}, "sandbox_failed_after_target"),
        ({}, "sandbox_failed_after_target"),
        ({"phase": None}, "sandbox_failed_after_target"),
        ({"phase": "before"}, "sandbox_failed_after_target"),
        ({"phase": "BEFORE_TARGET"}, "sandbox_failed_after_target"),
    ],
    ids=["before", "after", "missing", "null", "other word", "other case"],
)
def test_only_a_sandbox_failure_recorded_before_the_target_is_one_the_server_cannot_cause(
    phase, cause
):
    """Before the target the server did not exist yet, so a failure there is not the
    server's. Anything else, an unsaid phase included, may be, and keeps the key that stays in
    the worst case. Either way the run is sandbox_failed, exit 5."""
    judged = verdict.assess(
        [started(), {"type": "sandbox_failed", "condition": "probe", **phase}, ENDED, finished()]
    )
    assert judged.causes == [cause]
    assert (judged.state, judged.exit_code) == (verdict.SANDBOX_FAILED, 5)


def test_two_sandbox_failures_either_side_of_the_target_name_both_causes():
    judged = verdict.assess(
        [
            started(),
            {"type": "sandbox_failed", "condition": "probe", "phase": "before_target"},
            {"type": "sandbox_failed", "condition": "record", "phase": "after_target"},
            ENDED,
            finished(),
        ]
    )
    assert judged.causes == ["sandbox_failed", "sandbox_failed_after_target"]


def test_a_server_message_that_is_not_utf8_has_its_own_cause_beside_the_bounded_count():
    """The recorder marks it, the inspector counts it as bounded, and both causes stand."""
    judged = verdict.assess(
        [started(), UNDECODABLE, UNDECODABLE, ENDED, finished(inspection_bounded=2)]
    )
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["inspection_bounded", "message_undecodable"], judged.problems
    assert "2 server message(s) were not valid UTF-8" in " ".join(judged.problems)


def test_a_client_message_that_is_not_utf8_is_not_held_against_the_server():
    """What the client sent is not the server delivering content: the run is incomplete for a
    cause of its own, never ``message_undecodable`` (decided 2026-10-16)."""
    client = {**UNDECODABLE, "direction": "client_to_server"}
    judged = verdict.assess([started(), client, ENDED, finished(client_undecodable=1)])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["client_message_undecodable"], judged.problems
    assert "1 client message(s) were not valid UTF-8" in " ".join(judged.problems)


def test_any_other_unparseable_server_message_has_no_such_cause():
    """Only the recorder's ``not_utf8`` names it; invalid JSON is the inspector's to count."""
    other = {**UNDECODABLE, "parse": {"ok": False, "error_reason": "invalid_json"}}
    judged = verdict.assess([started(), other, ENDED, finished()])
    assert "message_undecodable" not in judged.causes


CLIENT_UNDECODABLE = {**UNDECODABLE, "direction": "client_to_server"}


def test_a_client_message_whose_event_was_dropped_is_still_counted():
    """The count in run_finished survives a message event dropped from a full queue."""
    judged = verdict.assess([started(), ENDED, finished(client_undecodable=2)])
    assert judged.causes == ["client_message_undecodable"], judged.problems
    assert "2 client message(s)" in " ".join(judged.problems)


def test_a_client_message_marked_in_a_recording_without_the_count_is_still_counted():
    """A recording written before the count existed reads 0 there; the mark alone is enough."""
    judged = verdict.assess([started(), CLIENT_UNDECODABLE, ENDED, finished()])
    assert judged.causes == ["client_message_undecodable"], judged.problems


def test_the_mark_and_the_count_of_the_same_message_say_one():
    judged = verdict.assess([started(), CLIENT_UNDECODABLE, ENDED, finished(client_undecodable=1)])
    assert "1 client message(s)" in " ".join(judged.problems)


def test_both_directions_undecodable_name_both_causes():
    judged = verdict.assess(
        [started(), UNDECODABLE, CLIENT_UNDECODABLE, ENDED,
         finished(inspection_bounded=1, client_undecodable=1)]
    )  # fmt: skip
    assert judged.causes == [
        "client_message_undecodable", "inspection_bounded", "message_undecodable"
    ], judged.problems  # fmt: skip


def test_no_client_message_undecodable_is_complete():
    judged = verdict.assess([started(), ENDED, finished(client_undecodable=0)])
    assert judged.state == verdict.COMPLETE, judged.problems


@pytest.mark.parametrize("value", ["1", True, -1, None, 1.0, [1]])
def test_a_client_count_that_is_no_count_is_not_taken_for_zero(value):
    judged = verdict.assess([started(), ENDED, finished(client_undecodable=value)])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["client_message_undecodable"], judged.problems


# -- over Streamable HTTP (rules version 8) --------------------------------------------------

HTTP_RUN = {"transport": "streamable-http"}
COUNTS = {"exchanges": 3, "responses": {"2xx": 3}, "streams": 0, "events": 0, "framing_errors": 0}


@pytest.mark.parametrize(
    ("reason", "cause"),
    [
        ("http_unreachable", "http_unreachable"),
        ("http_status", "http_status"),
        ("session_lost", "session_lost"),
        ("http_sse_only", "http_sse_only"),
        ("tls", "tls"),
        ("unauthorized", "unauthorized"),
        ("no_answer", "server_failed"),
    ],
)
def test_a_handshake_that_failed_for_a_reason_only_http_knows_is_named_by_it(reason, cause):
    """The state is server_failed as for any handshake; the cause says why, in HTTP's words."""
    judged = verdict.assess(
        [
            started(**HTTP_RUN),
            {"type": "server_failed", "reason": reason},
            ENDED,
            finished(http=COUNTS),
        ]
    )
    assert judged.state == verdict.SERVER_FAILED
    assert cause in judged.causes and cause in verdict.CAUSES


@pytest.mark.parametrize(
    "reason",
    ["http_status", "session_lost", "http_unreachable", "tls", "unauthorized", "stream_broken"],
)
def test_a_step_unanswered_for_an_http_reason_is_incomplete_with_that_cause(reason):
    """Not weaker than over stdio: incomplete, the inventory partial; the cause names it."""
    step = {"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": reason}
    skipped = {"type": "step_skipped", "step": "prompts/list", "reason": reason}
    judged = verdict.assess([started(**HTTP_RUN), step, skipped, ENDED, finished(http=COUNTS)])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == sorted([reason, "step_not_sent"]), judged.problems


def test_an_http_run_without_its_forwarding_counts_is_incomplete():
    judged = verdict.assess([started(**HTTP_RUN), ENDED, finished()])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["http_counts_missing"]


def test_an_http_run_with_its_counts_and_nothing_short_is_complete():
    judged = verdict.assess([started(**HTTP_RUN), ENDED, finished(http=COUNTS)])
    assert judged.state == verdict.COMPLETE, judged.problems


def test_a_handshake_that_failed_on_tls_names_the_library_s_text_in_the_problem():
    """Rules 11: the cause is ``tls``, the state server_failed, the text as recorded."""
    failed = {"type": "server_failed", "reason": "tls", "detail": "certificate verify failed"}
    judged = verdict.assess([started(**HTTP_RUN), failed, ENDED, finished(http=COUNTS)])
    assert (judged.state, judged.causes) == (verdict.SERVER_FAILED, ["tls"])
    assert judged.problems == ["server_failed: tls (certificate verify failed)"]


CHALLENGE = {
    "scheme": "Bearer",
    "params": {"error": "invalid_token", "resource_metadata": "https://auth.example.test/meta"},
}


def refused(status):
    """The recorded answer of an endpoint that refused: the challenge parsed, no token anywhere."""
    return {
        "type": "http_response",
        "status": status,
        "headers": {"www-authenticate": [CHALLENGE]},
    }


@pytest.mark.parametrize("status", [401, 403])
def test_a_first_answer_of_401_or_403_is_server_failed_unauthorized(status):
    """Rules 12: the cause is ``unauthorized``, the state server_failed; the challenge stays
    in the recording as recorded, and the verdict reads nothing of it."""
    failed = {"type": "server_failed", "reason": "unauthorized", "detail": f"HTTP {status}"}
    judged = verdict.assess(
        [started(**HTTP_RUN), refused(status), failed, ENDED, finished(http=COUNTS)]
    )
    assert (judged.state, judged.causes) == (verdict.SERVER_FAILED, ["unauthorized"])
    assert judged.problems == [f"server_failed: unauthorized (HTTP {status})"]
    assert verdict.CAUSES["unauthorized"]


def test_a_401_after_a_successful_answer_is_incomplete_unauthorized():
    """A later refusal is a step unanswered; the steps behind it were not sent."""
    ok = {"type": "http_response", "status": 200, "headers": {}}
    step = {"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": "unauthorized"}
    skipped = {"type": "step_skipped", "step": "prompts/list", "reason": "unauthorized"}
    judged = verdict.assess(
        [started(**HTTP_RUN), ok, refused(401), step, skipped, ENDED, finished(http=COUNTS)]
    )
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == sorted(["unauthorized", "step_not_sent"]), judged.problems


def test_the_challenge_is_in_the_recording_and_no_token_is_judged_into_the_verdict():
    """The parsed challenge is part of what is recorded; a token never is, so the problems
    carry none."""
    secret = "tk" + "x" * 12
    failed = {"type": "server_failed", "reason": "unauthorized", "detail": "***REDACTED***"}
    events = [started(**HTTP_RUN), refused(401), failed, ENDED, finished(http=COUNTS)]
    judged = verdict.assess(events)
    assert events[1]["headers"]["www-authenticate"] == [CHALLENGE]
    assert secret not in repr(events) and secret not in repr(judged.problems)


@pytest.mark.parametrize(
    "tls",
    [
        None,
        {"versions": ["TLSv1.3"], "certificates": ["ab" * 32]},
        {"versions": ["TLSv1.2", "TLSv1.3"], "certificates": ["ab" * 32, "cd" * 32]},
        "not an account",
    ],
)
def test_the_run_s_tls_set_is_not_judged(tls):
    """``run_finished.http.tls`` is a fact the store reads, not a count: a run with it, of
    whatever shape, is judged exactly as the same run without it."""
    events = [{"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": "no_answer"}]
    for tail in ([ENDED], events + [ENDED]):
        without = verdict.assess([started(**HTTP_RUN), *tail, finished(http=COUNTS)])
        with_tls = verdict.assess(
            [started(**HTTP_RUN), *tail, finished(http={**COUNTS, "tls": tls})]
        )
        assert (with_tls.state, with_tls.causes, with_tls.problems) == (
            without.state,
            without.causes,
            without.problems,
        )


def test_a_stdio_run_needs_no_http_counts():
    """The counts belong to the HTTP proxy; a stdio run is judged as before."""
    judged = verdict.assess([started(transport="stdio"), ENDED, finished()])
    assert judged.state == verdict.COMPLETE, judged.problems


@pytest.mark.parametrize("reason", [[], {}, ["http_status"], 7, None])
def test_a_reason_that_is_no_string_is_judged_as_before_not_a_crash(reason):
    """A damaged recording: the state and the old cause, never an exception."""
    failed = verdict.assess([started(), {"type": "server_failed", "reason": reason}, ENDED,
                             finished()])  # fmt: skip
    assert failed.state == verdict.SERVER_FAILED and "server_failed" in failed.causes
    step = {"type": "step_unanswered", "step": "tools/list", "pages": 0, "reason": reason}
    unanswered = verdict.assess([started(), step, ENDED, finished()])
    assert unanswered.causes == ["step_unanswered"]
    skipped = {"type": "step_skipped", "step": "tools/list", "reason": reason}
    left_out = verdict.assess([started(), skipped, ENDED, finished()])
    # Not a step the server declined: a step not sent, the inventory partial.
    assert left_out.state == verdict.INCOMPLETE and left_out.causes == ["step_not_sent"]


@pytest.mark.parametrize(
    "http",
    [
        "x",
        [],
        3,
        True,
        {},
        {"exchanges": 3},
        dict.fromkeys(("exchanges", "responses", "streams", "events", "framing_errors")),
        {**COUNTS, "exchanges": "3"},
        {**COUNTS, "exchanges": -1},
        {**COUNTS, "events": True},
        {**COUNTS, "streams": 1.0},
        {**COUNTS, "responses": [3]},
        {**COUNTS, "responses": {"2xx": None}},
    ],
)
def test_http_counts_that_are_no_object_are_missing(http):
    """Only a mapping with every count in it is the account of what was forwarded; anything
    else, an empty or partial mapping too, is no account."""
    judged = verdict.assess([started(**HTTP_RUN), ENDED, finished(http=http)])
    assert judged.causes == ["http_counts_missing"]


def test_the_counts_the_proxy_writes_are_the_counts_judged():
    """One list of words in mcp_kymograph.events: what the proxy writes is what the verdict asks."""
    from mcp_kymograph.events import HTTP_COUNTS
    from mcp_kymograph.http_proxy import _Tally

    # The counts, then the run's TLS set beside them (null over plain HTTP), which is no count.
    assert tuple(_Tally().as_dict()) == (*HTTP_COUNTS, "tls")
    judged = verdict.assess([started(**HTTP_RUN), ENDED, finished(http=_Tally().as_dict())])
    assert judged.state == verdict.COMPLETE, judged.problems


# -- tool calls of a script (rules version 9) ------------------------------------------------

CALLED = {"type": "step_called", "step": "tools/call", "tool": "fetch", "arguments": {}}


def call_failed(kind="rpc_error", code=-32000, tool="fetch"):
    return {"type": "call_failed", "step": "tools/call", "tool": tool, "kind": kind, "code": code}


def test_a_call_answered_with_a_result_leaves_the_run_complete():
    judged = verdict.assess([started(), CALLED, ENDED, finished()])
    assert judged.state == verdict.COMPLETE, judged.problems


@pytest.mark.parametrize(
    ("kind", "code", "cause"),
    [("rpc_error", -32000, "call_error"), ("rpc_error", None, "call_error"),
     ("tool_error", None, "tool_error")],
)  # fmt: skip
def test_a_call_answered_with_an_error_is_call_failed_named_by_its_kind(kind, code, cause):
    """The server answered: no failure of the run, and no result about content that never came."""
    judged = verdict.assess([started(), CALLED, call_failed(kind, code), ENDED, finished()])
    assert judged.state == verdict.CALL_FAILED
    assert judged.causes == [cause], judged.problems
    assert judged.exit_code == verdict.EXIT_CALL_FAILED == 6
    assert "fetch" in judged.problems[0]


def test_missing_data_outranks_a_failed_call():
    """A run that lacks data is incomplete, whatever its calls did."""
    judged = verdict.assess([started(), CALLED, call_failed(), ENDED, finished(unwritten_events=1)])
    assert judged.state == verdict.INCOMPLETE
    assert "call_error" in judged.causes and "unwritten_events" in judged.causes


def test_a_failed_call_does_not_outrank_a_failed_server():
    assert verdict.gravest([verdict.CALL_FAILED, verdict.SERVER_FAILED]) == verdict.SERVER_FAILED
    assert verdict.gravest([verdict.CALL_FAILED, verdict.INCOMPLETE]) == verdict.INCOMPLETE
    assert verdict.gravest([verdict.CALL_FAILED]) == verdict.CALL_FAILED


def test_an_unreadable_answer_to_a_call_is_incomplete_with_its_own_cause():
    """Named for what it was, not as a step that went unanswered."""
    step = {
        "type": "step_unanswered",
        "step": "tools/call",
        "pages": 0,
        "reason": "answer_unreadable",
    }
    judged = verdict.assess([started(), CALLED, step, ENDED, finished()])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["call_result_unreadable"], judged.problems


def test_a_call_that_was_not_answered_is_a_step_unanswered_as_before():
    step = {"type": "step_unanswered", "step": "tools/call", "pages": 0, "reason": "no_answer"}
    judged = verdict.assess([started(), CALLED, step, ENDED, finished()])
    assert judged.causes == ["step_unanswered"], judged.problems


def test_a_call_to_a_tool_the_listing_did_not_deliver_was_not_sent():
    skipped = {"type": "step_skipped", "step": "tools/call", "reason": "tool_not_listed"}
    judged = verdict.assess([started(), skipped, ENDED, finished()])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["step_not_sent"], judged.problems


@pytest.mark.parametrize(
    "event", [call_failed(kind="weird"), call_failed(kind=None), call_failed(tool=7),
              {"type": "call_failed", "step": "tools/call"}]
)  # fmt: skip
def test_a_call_failed_record_that_is_not_one_is_never_complete(event):
    judged = verdict.assess([started(), CALLED, event, ENDED, finished()])
    assert judged.state == verdict.INCOMPLETE
    assert judged.causes == ["call_record_unreadable"], judged.problems


def test_the_verdict_command_exits_with_six_for_a_failed_call(tmp_path, capsys):
    from test_rules_version import write

    path = write(tmp_path / "events.jsonl", [started(), CALLED, call_failed(), ENDED, finished()])
    assert cli.main(["verdict", "-q", str(path)]) == cli.EXIT_CALL_FAILED == 6


def test_a_run_whose_call_was_answered_with_an_error_is_filed_as_call_failed(tmp_path):
    """The store holds the new state like any other, and ``store ingest`` exits with its code."""
    path = recording(tmp_path, [], extra=[{"seq": 2, **CALLED}, {"seq": 3, **call_failed()}])
    database = str(tmp_path / "store.sqlite")
    assert cli.main(["store", "ingest", "-q", "--store", database, str(path)]) == 6
    with Store.open(database) as store:
        assert [run.state for run in store.runs()] == [verdict.CALL_FAILED]


def test_the_store_s_tables_take_every_state_the_verdict_and_the_fleet_give(tmp_path):
    """The states are listed in the store's SQL as well; a state added to the verdict and not
    there would refuse every run in it."""
    with Store.open(tmp_path / "store.sqlite"):
        pass
    connection = sqlite3.connect(tmp_path / "store.sqlite")
    try:
        tables = dict(
            connection.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")
        )
    finally:
        connection.close()
    assert [s for s in verdict.STATES if f"'{s}'" not in tables["runs"]] == []
    assert [s for s in fleet.STATES if f"'{s}'" not in tables["fleet_results"]] == []


@pytest.mark.parametrize(
    ("mode", "said"),
    [
        ("rpc-error", "call_failed [call_error] (the call of tool tool_0 was answered with a "
         "JSON-RPC error (-32000)"),
        ("tool-error", "call_failed [tool_error] (the call of tool tool_0 was answered with a "
         "result that says isError"),
    ],
)  # fmt: skip
def test_the_terminal_names_the_failed_call_by_its_tool_and_its_kind(tmp_path, capsys, mode, said):
    from test_script import TWO_CALLS, called_script

    called_script(tmp_path, "--call-result", mode, text=TWO_CALLS, expect=(6,))
    assert said in " ".join(capsys.readouterr().err.split())


@pytest.mark.parametrize(
    "lines",
    [
        [started(), finished()],
        [started(schema_version=SCHEMA_VERSION + 1), finished()],
        [started(), "{not json"],
        [],
    ],
    ids=["complete", "another schema", "a line that is not JSON", "empty"],
)
def test_judging_the_bytes_a_caller_read_is_reading_the_file(tmp_path, lines):
    """verdict.judge is verdict.read for a caller that read the bytes itself (the web views)."""
    path = tmp_path / "events.jsonl"
    path.write_text(
        "".join((line if isinstance(line, str) else json.dumps(line)) + "\n" for line in lines)
    )

    judged = verdict.judge(*verdict.read_events(path.read_bytes()))

    assert judged.shortfalls == verdict.read(path).shortfalls


def test_a_recording_that_cannot_be_read_is_judged_as_read_judges_it(tmp_path):
    missing = tmp_path / "absent" / "events.jsonl"
    try:
        missing.read_bytes()
    except OSError as exc:
        judged = verdict.unreadable(exc)

    assert judged.shortfalls == verdict.read(missing).shortfalls
    assert judged.causes == ["unreadable"]


def test_a_stop_for_an_unsupported_protocol_is_server_failed_with_that_cause():
    """Rules 12: the detection of the generation stopped; no listing was sent."""
    failed = {"type": "server_failed", "reason": "protocol_unsupported", "detail": "modern_refused"}
    judged = verdict.assess([started(**HTTP_RUN), failed, ENDED, finished(http=COUNTS)])
    assert (judged.state, judged.causes) == (verdict.SERVER_FAILED, ["protocol_unsupported"])
    assert verdict.CAUSES["protocol_unsupported"] and verdict.CAUSES["stream_broken"]
