"""A server that never starts is a server that failed — never a traceback, never exit 1.

The command not found, a file that is not executable, one in no format the system can run,
a server that ends at once with or without an error: in either mode the run is server_failed,
exits 4, and its recording says why. Run as a process of its own, so the exit code and the
absence of a traceback are what a caller sees.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import verdict

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
SERVER = Path(__file__).parent / "fixtures" / "discovery_server.py"

#: Commands that cannot be started, and what the recording must say about each.
NOT_STARTED = {
    "missing": "the command was not found (ENOENT)",
    "not-executable": "the command is not executable (permission denied) (EACCES)",
    "no-format": "the command is not in a format the system can execute (ENOEXEC)",
}


def command(tmp_path: Path, case: str) -> list[str]:
    if case == "missing":
        return [str(tmp_path / "no-such-server")]
    if case == "not-executable":
        path = tmp_path / "server.sh"
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o644)
        return [str(path)]
    if case == "no-format":
        path = tmp_path / "server.txt"
        path.write_text("echo hello\n")
        path.chmod(0o755)
        return [str(path)]
    if case == "error-at-once":
        return [sys.executable, "-c", "import sys; sys.stderr.write('boom\\n'); sys.exit(3)"]
    return [sys.executable, "-c", "pass"]  # ends at once, without an error


def start(tmp_path: Path, mode: str, case: str) -> tuple[subprocess.CompletedProcess, list]:
    out = tmp_path / "runs"
    extra = ["--step-timeout", "5"] if mode == "drive" else []
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", mode, "-q", "--out-dir", str(out), *extra,
         "--", *command(tmp_path, case)],
        input=INITIALIZE, capture_output=True, timeout=120, check=False,
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return done, path


@pytest.mark.parametrize("mode", ["run", "drive"])
@pytest.mark.parametrize("case", list(NOT_STARTED))
def test_a_command_that_cannot_be_started_is_server_failed_and_the_recording_says_why(
    tmp_path, mode, case
):
    done, path = start(tmp_path, mode, case)
    assert done.returncode == verdict.EXIT_SERVER_FAILED, done.stderr.decode()
    assert b"Traceback" not in done.stderr
    events = [json.loads(line) for line in path.read_text().splitlines()]
    (failed,) = [e for e in events if e["type"] == "server_failed"]
    assert (failed["reason"], failed["detail"]) == ("not_started", NOT_STARTED[case])
    assert events[-1]["type"] == "run_finished"
    assert events[-1]["reason"] == "server_not_started"
    judged = verdict.read(path)
    assert judged.state == verdict.SERVER_FAILED
    assert f"server_failed: not_started ({NOT_STARTED[case]})" in judged.problems
    assert b"the server could not be started: " + NOT_STARTED[case].encode() in done.stderr
    if mode == "run":
        assert b"server_failed: its command could not be started" in done.stderr


@pytest.mark.parametrize("mode", ["run", "drive"])
@pytest.mark.parametrize(("case", "ended"), [("error-at-once", "exit code 3"),
                                             ("ends-at-once", "exit code 0")])  # fmt: skip
def test_a_server_that_ends_at_once_without_a_word_is_server_failed(tmp_path, mode, case, ended):
    """It started, and said nothing before it ended — with an error or without. In proxy mode
    its own code is not handed through: there was nothing to observe it by."""
    done, path = start(tmp_path, mode, case)
    assert done.returncode == verdict.EXIT_SERVER_FAILED, done.stderr.decode()
    assert b"Traceback" not in done.stderr
    events = [json.loads(line) for line in path.read_text().splitlines()]
    closing = events[-1]
    assert (closing["type"], closing["server_output_bytes"]) == ("run_finished", 0)
    assert closing["client_input_bytes"] > 0
    judged = verdict.read(path)
    assert judged.state == verdict.SERVER_FAILED
    assert "server_silent" in judged.causes
    (silent,) = [p for p in judged.problems if p.startswith("server_silent:")]
    assert f"ended ({ended})" in silent
    if mode == "run":
        assert b"server_failed: it wrote nothing to its stdout" in done.stderr


def test_a_server_that_ends_while_a_silent_client_still_waits_is_server_failed(tmp_path):
    """Nobody wrote anything — but the server ended on its own, its client still connected.
    That is not an empty session the client closed; it is a server that did not serve."""
    out = tmp_path / "runs"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "run", "-q", "--out-dir", str(out), "--",
         sys.executable, "-c", "import sys; sys.exit(2)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )  # fmt: skip
    try:
        code = process.wait(timeout=60)  # ends without our stdin ever closing
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=60)
    assert code == verdict.EXIT_SERVER_FAILED
    (path,) = out.glob("*/events.jsonl")
    closing = json.loads(path.read_text().splitlines()[-1])
    assert (closing["client_input_bytes"], closing["server_exited_first"]) == (0, True)
    assert "server_silent" in verdict.read(path).causes


def test_a_proxied_server_that_answered_and_then_failed_still_hands_its_code_through(tmp_path):
    out = tmp_path / "runs"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "run", "-q", "--out-dir", str(out), "--",
         sys.executable, str(SERVER), "--exit-code", "7"],
        input=INITIALIZE, capture_output=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 7
    (path,) = out.glob("*/events.jsonl")
    assert verdict.read(path).state == verdict.COMPLETE


def test_an_empty_proxied_session_is_incomplete_not_a_failed_server(tmp_path):
    """Neither side said anything, and the client ended it: nothing failed, and nothing was
    observed. Not server_failed — the server was asked nothing — and not complete either: a
    session about nothing is not a result. The exit code stays the server's."""
    out = tmp_path / "runs"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "run", "--out-dir", str(out), "--",
         sys.executable, str(SERVER)],
        input=b"", capture_output=True, timeout=120, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr.decode()
    assert b"nobody said anything in this session" in done.stderr
    assert b"(empty_session); exit code 0 is the server's own" in done.stderr
    (path,) = out.glob("*/events.jsonl")
    closing = json.loads(path.read_text().splitlines()[-1])
    assert (closing["client_input_bytes"], closing["server_exited_first"]) == (0, False)
    judged = verdict.read(path)
    assert (judged.state, judged.causes) == (verdict.INCOMPLETE, ["empty_session"])


@pytest.mark.parametrize(
    ("before", "causes"),
    [
        ([], []),
        ([{"type": "server_failed", "reason": "not_started", "detail": "ENOENT"}],
         ["server_failed"]),
        ([{"type": "sandbox_failed", "condition": "probe", "phase": "before_target"}],
         ["sandbox_failed"]),
    ],
    ids=["no-server-exit-recorded", "never-started", "sandbox-before-target"],
)  # fmt: skip
def test_a_run_whose_server_never_ran_is_not_also_an_empty_session(before, causes):
    """0, 0 and no exit is also how a run without a server closes: its graver state already
    says why nothing was said, and no second cause is made up for it."""
    closing = {"type": "run_finished", "findings_by_statement": {}, "server_output_bytes": 0,
               "client_input_bytes": 0, "server_exited_first": False}  # fmt: skip
    started = {"type": "run_started", "mode": "proxy", "isolation": "host"}
    assert verdict.assess([started, *before, closing]).causes == causes


def test_an_empty_session_is_judged_from_the_recording_wherever_the_server_ran():
    closing = {"type": "run_finished", "findings_by_statement": {}, "server_output_bytes": 0,
               "client_input_bytes": 0, "server_exited_first": False}  # fmt: skip
    started = {"type": "run_started", "mode": "proxy", "isolation": "host"}
    exited = {"type": "server_exited", "exit_code": 0, "signal": None}
    judged = verdict.assess([started, exited, closing])
    assert (judged.state, judged.causes) == (verdict.INCOMPLETE, ["empty_session"])
    assert verdict.empty_session(0, 0, False) is True
    for output, given, first in ((1, 0, False), (0, 1, False), (0, 0, True)):
        assert verdict.empty_session(output, given, first) is False


@pytest.mark.parametrize(
    ("output", "given", "first", "silent"),
    [
        (0, 165, False, True),   # asked, said nothing
        (0, 0, True, True),      # ended while its client was still there
        (0, 0, False, False),    # nobody said anything, the client ended it
        (1, 165, True, False),   # said something
        (1, 0, False, False),
    ],
)  # fmt: skip
def test_what_counts_as_a_silent_server(output, given, first, silent):
    assert verdict.server_silent(output, given, first) is silent
    closing = {"type": "run_finished", "findings_by_statement": {}, "server_output_bytes": output,
               "client_input_bytes": given, "server_exited_first": first}  # fmt: skip
    started = {"type": "run_started", "mode": "proxy", "isolation": "host"}
    judged = verdict.assess([started, closing])
    assert (judged.state == verdict.SERVER_FAILED) is silent
    assert ("server_silent" in judged.causes) is silent


@pytest.mark.parametrize("missing", ["server_output_bytes", "client_input_bytes",
                                     "server_exited_first"])  # fmt: skip
def test_a_closing_event_that_does_not_say_what_was_written_is_incomplete(missing):
    closing = {"type": "run_finished", "findings_by_statement": {}, "server_output_bytes": 9,
               "client_input_bytes": 9, "server_exited_first": False}  # fmt: skip
    del closing[missing]
    started = {"type": "run_started", "mode": "proxy", "isolation": "host"}
    judged = verdict.assess([started, closing])
    assert (judged.state, judged.causes) == (verdict.INCOMPLETE, ["server_output_unknown"])
