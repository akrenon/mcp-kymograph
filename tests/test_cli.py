"""The command line: argument handling, the startup order, and terminal safety."""

import asyncio
import contextlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli

TOY = str(Path(__file__).parent / "fixtures" / "toy_server.py")
CANARY = "CANARY-do-not-leak-0123456789"


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git")
    assert git, "these tests need a git binary"
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=path, check=True)  # noqa: S603
    return path


# -- arguments ------------------------------------------------------------------------


def test_the_server_command_is_taken_verbatim_after_the_separator():
    ours, server = cli.split_server_command(["run", "--quiet", "--", "srv", "--mode", "--quiet"])
    assert ours == ["run", "--quiet"]
    assert server == ["srv", "--mode", "--quiet"], "our flags must not be parsed out of theirs"


def test_a_missing_server_command_is_refused_not_guessed(tmp_path, capsys):
    assert cli.main(["run", "--out-dir", str(tmp_path / "runs")]) == cli.EXIT_REFUSED
    assert "--" in capsys.readouterr().err


# -- the startup order ----------------------------------------------------------------


def test_a_refused_destination_starts_no_process(tmp_path, monkeypatch, capsys):
    """The order is the safety property: check the destination, then start anything.

    A user who sees a refusal and still has a server running would not notice.
    """
    repo = make_repo(tmp_path / "repo")  # not ignored, so the destination is refused
    started = []

    async def must_not_run(*args, **kwargs):
        started.append(args)
        raise AssertionError("a server was started despite the destination being refused")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)

    code = cli.main(["run", "--out-dir", str(repo / "runs"), "--", sys.executable, TOY])

    assert code == cli.EXIT_REFUSED
    assert started == []
    assert "git working tree" in capsys.readouterr().err


def test_a_refused_destination_leaves_no_run_directory_behind(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")

    async def must_not_run(*args, **kwargs):
        raise AssertionError("no server may be started")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)
    cli.main(["run", "--out-dir", str(repo / "runs"), "--", sys.executable, TOY])

    assert not (repo / "runs").exists()


# -- nothing from the traffic reaches the terminal unfiltered --------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "tools/call\r\x1b[2Kfake",  # rewrites the line it was printed on
        "tools/‮call",  # bidi override
        "tools/​call",  # zero-width space
        "tools/call\x00\x07",  # NUL and bell
        "tools/call\U000e0041",  # a tag character
    ],
)
def test_every_display_value_is_stripped_of_anything_with_an_effect(hostile):
    shown = cli.display(hostile)
    assert "\x1b" not in shown
    assert all(character.isprintable() or character == " " for character in shown)


def test_display_values_are_capped():
    assert len(cli.display("m" * 500, limit=40)) == 40


def test_a_request_id_goes_through_the_same_filter_as_a_method(capsys):
    """A single unfiltered insert is enough; the id is as much the server's choice."""
    from mcp_kymograph.events import Direction, Encoding, Message, ParseKind, ParseResult, Payload

    view = cli.TerminalView(sys.stderr)
    view.event(
        1,
        Message(
            direction=Direction.SERVER_TO_CLIENT,
            transport="stdio",
            size_bytes=10,
            truncated=False,
            payload=Payload(encoding=Encoding.TEXT, data=""),
            parse=ParseResult(ok=True, kind=ParseKind.RESPONSE, id="7\x1b[2Kspoof"),
        ),
    )
    line = capsys.readouterr().err
    assert "\x1b" not in line
    assert "7" in line


# -- the protocol channel -------------------------------------------------------------


def test_claiming_stdout_points_descriptor_one_at_stderr():
    script = """
import os, sys
from mcp_kymograph.cli import claim_protocol_stdout
protocol = claim_protocol_stdout()
print("this must not reach the client")          # goes to fd 1, which is now stderr
protocol.write(b"protocol\\n"); protocol.flush()
"""
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, check=True
    )
    assert done.stdout == b"protocol\n", "only the proxy may write to the client's channel"
    assert b"this must not reach the client" in done.stderr


def test_claiming_stdout_falls_back_to_the_null_device_without_a_stderr(tmp_path):
    """A client may start us with no stderr at all.

    Descriptor 2 is closed after the fork and before the exec, so the interpreter comes up
    without a stderr the way it really would. Closing it from inside the script instead
    would not test this: the import machinery takes the free descriptor for itself, and the
    scenario is gone before the code under test runs.
    """
    marker = tmp_path / "protocol.txt"
    script = f"""
import os
from mcp_kymograph.cli import claim_protocol_stdout
protocol = claim_protocol_stdout()
os.write(1, b"this must be swallowed")     # descriptor 1 now leads nowhere
protocol.write(b"protocol\\n")
protocol.flush()
open({str(marker)!r}, "w").write("reached the end")
os._exit(0)
"""
    with open(tmp_path / "client.txt", "wb") as client_channel:
        subprocess.run(  # noqa: S603
            [sys.executable, "-c", script],
            stdout=client_channel,
            preexec_fn=lambda: os.close(2),  # noqa: PLW1509 - the point of the test
            check=True,
        )

    assert marker.read_text() == "reached the end", "a missing stderr must not be fatal"
    assert (tmp_path / "client.txt").read_bytes() == b"protocol\n", (
        "descriptor 1 must not still be pointing at the client's channel"
    )


# -- end to end -----------------------------------------------------------------------


def run_cli(tmp_path, *server_args, stdin: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "run",
            "--out-dir",
            str(tmp_path / "runs"),
            "--",
            sys.executable,
            TOY,
            *server_args,
        ],
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
    )


def recording_of(tmp_path) -> list[dict]:
    (path,) = list((tmp_path / "runs").glob("*/events.jsonl"))
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_a_whole_session_runs_and_the_client_sees_only_protocol(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    done = run_cli(tmp_path, "--mode", "stderr", stdin=request)

    assert done.returncode == 0
    for line in done.stdout.splitlines():
        assert json.loads(line)["id"] == 1, "the client's channel carries protocol and nothing else"
    assert b"toy: handling a request" in done.stderr, "the server's stderr goes to ours"

    events = recording_of(tmp_path)
    assert events[0]["type"] == "run_started"
    assert events[-1]["type"] == "run_finished"
    assert [event["seq"] for event in events] == list(range(1, len(events) + 1))


def test_the_servers_exit_code_is_passed_through(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    done = run_cli(tmp_path, "--mode", "crash_midway", stdin=request)
    assert done.returncode == 3, "the client must see the server's own outcome"


def test_a_credential_on_the_server_command_line_is_masked_in_a_real_run(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    run_cli(tmp_path, "--mode", "normal", "--api-key", CANARY, stdin=request)
    (path,) = list((tmp_path / "runs").glob("*/events.jsonl"))
    assert CANARY not in path.read_text()


def test_a_run_directory_is_created_per_run_and_kept_to_its_owner(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    run_cli(tmp_path, "--mode", "normal", stdin=request)
    (directory,) = list((tmp_path / "runs").glob("*"))
    assert os.stat(directory).st_mode & 0o077 == 0
    assert os.stat(directory / "events.jsonl").st_mode & 0o077 == 0


# -- the engagement gate --------------------------------------------------------------


def test_a_scenario_against_a_non_local_target_without_confirmation_starts_no_process(
    tmp_path, monkeypatch, capsys
):
    """The gate has legal weight: with a scenario active and a non-local target unconfirmed,
    the run is refused before any process starts and nothing is left behind."""
    started = []

    async def must_not_run(*args, **kwargs):
        started.append(args)
        raise AssertionError("no process may start when the engagement gate refuses")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)

    code = cli.main(
        [
            "run",
            "--out-dir",
            str(tmp_path / "runs"),
            "--scenario",
            "tool-poisoning",
            "--target",
            "example.com",
            "--",
            sys.executable,
            TOY,
        ]
    )

    assert code == cli.EXIT_REFUSED
    assert started == []
    assert not (tmp_path / "runs").exists(), "a refused run must leave no run directory"
    assert "engagement" in capsys.readouterr().err


def test_pure_observation_against_a_non_local_target_is_unaffected(tmp_path, monkeypatch):
    """Without a scenario the gate does not apply: Phase 1 behaviour is unchanged. The run
    proceeds to start a process (stubbed here so the test stays offline and fast)."""
    reached = []

    async def stub(*args, **kwargs):
        reached.append(args)
        raise RuntimeError("stop after the gate; we only check it did not refuse")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", stub)

    with contextlib.suppress(RuntimeError):
        cli.main(
            [
                "run",
                "--out-dir",
                str(tmp_path / "runs"),
                "--target",
                "example.com",
                "--",
                sys.executable,
                TOY,
            ]
        )

    assert reached, "observation without a scenario must not be gated"


def test_a_scenario_against_localhost_is_allowed_without_confirmation(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode() + b"\n"
    done = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "run",
            "--out-dir",
            str(tmp_path / "runs"),
            "--scenario",
            "tool-poisoning",
            "--",
            sys.executable,
            TOY,
        ],
        input=request,
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0
    (path,) = list((tmp_path / "runs").glob("*/events.jsonl"))
    events = [json.loads(line) for line in path.read_text().splitlines()]
    assert any(e["type"] == "intervention" for e in events), "the scenario ran"


# -- the rule-error policy is a run's setting, and a report has to be able to read it ----


def run_cli_with(tmp_path, our_args, *server_args, stdin: bytes) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "run",
            "--out-dir",
            str(tmp_path / "runs"),
            *our_args,
            "--",
            sys.executable,
            TOY,
            *server_args,
        ],
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_the_rule_error_policy_is_recorded_with_the_other_run_settings(tmp_path):
    """A recording cannot be judged without it: the same events mean different things when a
    failing rule ended the run and when it was stilled and the run went on."""
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    policy = ["--on-rule-error", "continue"]
    done = run_cli_with(tmp_path, policy, "--mode", "normal", stdin=request)

    assert done.returncode == 0
    events = recording_of(tmp_path)
    assert events[0]["limits"]["on_rule_error"] == "continue"


def test_the_recorded_default_is_abort(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    run_cli_with(tmp_path, [], "--mode", "normal", stdin=request)
    assert recording_of(tmp_path)[0]["limits"]["on_rule_error"] == "abort"


def test_an_unknown_policy_is_refused_rather_than_guessed(tmp_path):
    policy = ["--on-rule-error", "carry-on"]
    done = run_cli_with(tmp_path, policy, "--mode", "normal", stdin=b"")
    assert done.returncode != 0
    assert b"carry-on" in done.stderr
    assert not (tmp_path / "runs").exists(), "a rejected argument must leave nothing behind"


# -- the recording says what the run claimed about its own authorization ----------------


def test_a_real_run_records_the_authorization_it_was_started_under(tmp_path):
    """Without this the recording cannot say afterwards whether altering traffic was asserted
    to be covered by an engagement, and against which declared target. The gate has legal
    weight; a claim that leaves no trace in the evidence file is worth little."""
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode() + b"\n"
    flags = ["--scenario", "tool-poisoning", "--target", "10.0.0.5", "--engagement-confirmed"]
    done = run_cli_with(tmp_path, flags, "--mode", "normal", stdin=request)

    assert done.returncode == 0
    assert recording_of(tmp_path)[0]["authorization"] == {
        "scenario": "tool-poisoning",
        "scenario_digest": None,
        "declared_target": "10.0.0.5",
        "engagement_confirmed_flag": True,
        "rules_loaded": True,
        "engagement": None,
    }


def test_pure_observation_records_the_posture_it_actually_had(tmp_path):
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    run_cli_with(tmp_path, [], "--mode", "normal", stdin=request)
    assert recording_of(tmp_path)[0]["authorization"] == {
        "scenario": None,
        "scenario_digest": None,
        "declared_target": None,
        "engagement_confirmed_flag": False,
        "rules_loaded": False,
        "engagement": None,
    }


def test_rules_loaded_is_read_from_the_engine_not_from_the_flag(tmp_path):
    """The one fact among three claims. It is what makes the gate apply at all, so it is
    reported by the proxy from the engine it was given rather than taken on trust."""
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
    run_cli_with(tmp_path, ["--target", "10.0.0.5"], "--mode", "normal", stdin=request)
    recorded = recording_of(tmp_path)[0]["authorization"]
    assert recorded["declared_target"] == "10.0.0.5", "the claim is kept as made"
    assert recorded["rules_loaded"] is False, "and the fact contradicts nothing that was claimed"


def test_a_local_target_with_a_port_runs_a_scenario_without_confirmation(tmp_path):
    """The reason the split exists: a port does not move a target off the machine."""
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode() + b"\n"
    flags = ["--scenario", "tool-poisoning", "--target", "localhost:8080"]
    done = run_cli_with(tmp_path, flags, "--mode", "normal", stdin=request)
    assert done.returncode == 0, done.stderr
    assert recording_of(tmp_path)[0]["authorization"]["engagement_confirmed_flag"] is False


def test_a_port_on_an_unknown_host_is_still_refused(tmp_path):
    flags = ["--scenario", "tool-poisoning", "--target", "example.com:8080"]
    done = run_cli_with(tmp_path, flags, "--mode", "normal", stdin=b"")
    assert done.returncode == cli.EXIT_REFUSED
    assert not (tmp_path / "runs").exists()


# -- what opens the gate: the selection, not how many rules it happened to load ----------


def test_a_scenario_that_loads_no_rules_still_needs_the_confirmation(tmp_path, monkeypatch):
    """The precondition for scenario files. Until Phase 3 the gate asked
    the engine whether it had rules, so a scenario that loaded none — an empty file, a parse
    error, every rule filtered out — counted as pure observation and ran unconfirmed against
    any target. The intent to alter traffic is in the selection, not in the rule count."""
    started = []

    async def must_not_run(*args, **kwargs):
        started.append(args)
        raise AssertionError("no process may start when the engagement gate refuses")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)
    monkeypatch.setitem(cli.SCENARIOS, "empty-scenario", tuple)

    code = cli.main(
        [
            "run",
            "--out-dir",
            str(tmp_path / "runs"),
            "--scenario",
            "empty-scenario",
            "--target",
            "example.com",
            "--",
            sys.executable,
            TOY,
        ]
    )

    assert code == cli.EXIT_REFUSED, "a scenario with no rules must not slip past the gate"
    assert started == []
    assert not (tmp_path / "runs").exists()
