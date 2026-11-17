"""A run stopped by a signal says so, and is incomplete — not a failed server, not a failed
sandbox.

The proxy writes ``run_stopped`` the moment SIGINT or SIGTERM arrives, before the stop has any
consequence. The verdict reads the run as incomplete under the cause ``interrupted`` — the same
key a fleet's interruption gives a run it cut short — and holds nothing the stop brought about
against the server: a connection the stop closed, a server it killed before it answered. What
went wrong before the stop still counts. In driver mode the exit code is the run's state (3); in
proxy mode the server's own is handed through, and the terminal says the run is incomplete.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from mcp_kymograph import verdict
from test_fleet import docker

SPOKE = {"server_output_bytes": 100, "client_input_bytes": 100, "server_exited_first": False}
ENDED = {"type": "script_finished", "inventory": "complete"}
STOPPED = {"type": "run_stopped", "signal": "SIGINT"}
#: A server killed before it answered: it wrote nothing, its client did.
CUT = {"server_output_bytes": 0, "client_input_bytes": 165, "server_exited_first": False}
#: A server that wrote nothing and ended on its own while its client was still there.
CRASHED = {"server_output_bytes": 0, "client_input_bytes": 0, "server_exited_first": True}

INITIALIZE = (
    json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"}}}
    ).encode()
    + b"\n"
)  # fmt: skip
#: A server that never answers: the stop always comes before its first word.
MUTE = [sys.executable, "-c", "import time; time.sleep(120)"]


def started(mode="driver"):
    return {"type": "run_started", "mode": mode, "isolation": "host"}


def finished(**counts):
    return {"type": "run_finished", "findings_by_statement": {}, **(counts or SPOKE)}


def exited():
    return {"type": "server_exited", "exit_code": None, "signal": 15}


# -- the rule, on events ----------------------------------------------------------------------


def test_a_stopped_run_is_incomplete_under_interrupted():
    judged = verdict.assess([started(), STOPPED, ENDED, finished()])
    assert (judged.state, judged.causes) == (verdict.INCOMPLETE, ["interrupted"])
    assert "stopped by SIGINT before it ended" in judged.problems[0]


def test_what_the_stop_brought_about_is_not_held_against_the_server():
    """After the stop the driver saw its connection close; the server said nothing because it
    was killed first. Neither is the server failing."""
    events = [started(), STOPPED, {"type": "server_failed", "reason": "connection_closed"},
              exited(), finished(**CUT)]  # fmt: skip
    judged = verdict.assess(events)
    assert judged.state == verdict.INCOMPLETE, judged.problems
    assert judged.causes == ["interrupted", "no_script_finished"]


def test_what_failed_before_the_stop_still_counts():
    events = [started(), {"type": "server_failed", "reason": "no_answer"}, STOPPED, exited(),
              finished(**CUT)]  # fmt: skip
    judged = verdict.assess(events)
    assert judged.state == verdict.SERVER_FAILED
    assert {"interrupted", "server_failed"} <= set(judged.causes)


def test_a_server_that_ended_on_its_own_without_a_word_failed_even_if_a_stop_followed():
    events = [started(), exited(), STOPPED, ENDED, finished(**CRASHED)]
    judged = verdict.assess(events)
    assert judged.state == verdict.SERVER_FAILED
    assert {"interrupted", "server_silent"} <= set(judged.causes)


def test_a_stopped_session_in_which_nobody_spoke_is_interrupted_not_empty():
    events = [
        started("proxy"),
        STOPPED,
        exited(),
        finished(server_output_bytes=0, client_input_bytes=0, server_exited_first=False),
    ]
    assert verdict.assess(events).causes == ["interrupted"]  # fmt: skip


def test_without_the_stop_the_same_silence_is_the_server_s_failure():
    """The other direction: run_stopped is what makes the difference."""
    judged = verdict.assess([started(), exited(), ENDED, finished(**CUT)])
    assert (judged.state, judged.causes) == (verdict.SERVER_FAILED, ["server_silent"])


# -- as a caller sees it ----------------------------------------------------------------------


def stop_after(argv: list[str], delay: float, *, stdin: bytes = b"", number=signal.SIGINT):
    process = subprocess.Popen(  # noqa: S603
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    process.stdin.write(stdin)
    process.stdin.flush()
    time.sleep(delay)
    process.send_signal(number)
    try:
        out, err = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
    return process.returncode, err.decode()


def stop_when(argv: list[str], ready, *, number=signal.SIGINT, timeout: float = 60.0):
    """Like :func:`stop_after`, but the signal goes out once ``ready()`` says so, not after a
    fixed delay: a test about a stop *during* some phase must not race that phase's length."""
    process = subprocess.Popen(  # noqa: S603
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    deadline = time.monotonic() + timeout
    try:
        while not ready():
            if process.poll() is not None or time.monotonic() > deadline:
                process.kill()
                _, err = process.communicate(timeout=60)
                pytest.fail(f"the phase to stop in never began: {err.decode()}")
            time.sleep(0.02)
        process.send_signal(number)
        out, err = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
    return process.returncode, err.decode()


def recording(out: Path) -> tuple[Path, list[dict]]:
    (path,) = out.glob("*/events.jsonl")
    return path, [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM], ids=["SIGINT", "SIGTERM"])
def test_driver_mode_a_stop_before_the_server_answered_is_incomplete_and_exits_3(tmp_path, number):
    out = tmp_path / "runs"
    code, err = stop_after(
        [sys.executable, "-m", "mcp_kymograph.cli", "drive", "-q", "--out-dir", str(out),
         "--step-timeout", "60", "--", *MUTE],
        1.5, number=number,
    )  # fmt: skip
    assert "Traceback" not in err, err
    assert code == verdict.EXIT_INCOMPLETE, err
    assert "incomplete [interrupted" in err
    path, events = recording(out)
    stops = [e for e in events if e["type"] == "run_stopped"]
    assert [s["signal"] for s in stops] == [signal.Signals(number).name]
    assert events[-1]["type"] == "run_finished"
    judged = verdict.read(path)
    assert judged.state == verdict.INCOMPLETE, judged.problems
    assert "interrupted" in judged.causes and "server_silent" not in judged.causes
    assert "server_failed" not in judged.causes


def test_proxy_mode_a_stop_before_the_server_answered_is_incomplete_and_hands_its_code_through(
    tmp_path,
):
    out = tmp_path / "runs"
    code, err = stop_after(
        [sys.executable, "-m", "mcp_kymograph.cli", "run", "-q", "--out-dir", str(out), "--",
         *MUTE],
        1.5, stdin=INITIALIZE,
    )  # fmt: skip
    assert "Traceback" not in err, err
    assert code != verdict.EXIT_SERVER_FAILED, "the server was stopped, it did not fail"
    assert "stopped by SIGINT: the recording is incomplete (interrupted)" in err
    assert f"exit code {code} is the server's" in err
    path, events = recording(out)
    kinds = [e["type"] for e in events]
    assert kinds.index("run_stopped") < kinds.index("run_finished")
    assert events[-1]["client_input_bytes"] > 0 and events[-1]["server_output_bytes"] == 0
    judged = verdict.read(path)
    assert (judged.state, judged.causes) == (verdict.INCOMPLETE, ["interrupted"])


@docker
def test_a_stop_while_the_sandbox_is_built_is_incomplete_not_a_failed_sandbox(tmp_path):
    """Measured before the fix: SIGTERM while the sandbox is built made the run sandbox_failed and
    exit 5. Now it is incomplete, exits 3, no target was started, and the sandbox took its
    containers and its staging directory with it.

    The signal goes out once the sandbox's first container exists — the sink, the second of the
    five steps before the target — not after a fixed second: on a fast runner the whole build
    took less than that, the target was started, and the stop landed in the session instead.
    """
    from mcp_kymograph.sandbox import docker as docker_cli
    from test_fleet import write_manifest

    mute = ["{python}", "-c", "import time; time.sleep(120)"]
    manifest = write_manifest(tmp_path, {"name": "mute", "command": mute})
    out = tmp_path / "runs"
    nonce = "5c0ff5e7ab1e"
    code, err = stop_when(
        [sys.executable, "-m", "mcp_kymograph.cli", "drive", "-q", "--out-dir", str(out),
         "--manifest", str(manifest), "--entry", "mute", "--isolation", "runc",
         "--sandbox-nonce", nonce],
        lambda: bool(docker_cli.leftovers(f"mcp-kymograph.run={nonce}")), number=signal.SIGTERM,
    )  # fmt: skip
    assert "Traceback" not in err, err
    assert code == verdict.EXIT_INCOMPLETE, err
    path, events = recording(out)
    kinds = [e["type"] for e in events]
    assert "run_stopped" in kinds and "sandbox_failed" not in kinds, kinds
    assert (events[-1]["type"], events[-1]["reason"]) == ("run_finished", "stopped"), (
        "the closing event says the run was stopped, not that its sandbox failed"
    )
    assert not [e for e in events if e["type"] == "server_exited"], "no target was started"
    judged = verdict.read(path)
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes
    assert docker_cli.leftovers(f"mcp-kymograph.run={nonce}") == []
    assert list(Path(tempfile.gettempdir()).glob(f"mcp-kymograph-stage-{nonce}-*")) == []


def test_recordings_of_schema_2_made_before_run_stopped_are_refused_whole(tmp_path):
    """A schema 2 recording cannot say it was stopped: a stopped proxied run of that schema
    would read complete. So schema 3 is the only one read, and 2 is an earlier one."""
    from mcp_kymograph import events

    assert events.SCHEMA_VERSION == 5
    path = tmp_path / "events.jsonl"
    lines = [{"v": 2, "type": "run_started", "mode": "proxy", "isolation": "host",
              "schema_version": 2}, {"v": 2, **ENDED}, {"v": 2, **finished()}]  # fmt: skip
    path.write_text("".join(json.dumps(line) + "\n" for line in lines))
    judged = verdict.read(path)
    assert (judged.state, judged.causes) == (verdict.INCOMPLETE, ["schema"])
    assert "the recording is schema 2, made by an earlier version" in judged.problems[0]
