"""Active probes, part 2: the stop of a run (window, stop file, signal) and the module frame.

A run this tool drives itself ends when it is told to: the end of the engagement's window, the
stop file (``engagement stop``) and a signal each stop it before its next step, in order, with a
cause in the recording. A run it only observes is stopped by the stop file and a signal but not by
the window. The frame for probe modules (``drive --probe``) holds every request of a module to the
window, the stop file, its ``max_calls`` and the scope guard. The server is the discovery fixture
behind a launcher that writes down every byte it is sent, and can drop a file (the stop file, or a
flag the injected clock reads) the moment it sees ``tools/list``, so that the stop falls between
two steps without a race.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, eras, events, fleet, verdict
from mcp_kymograph import script as script_file
from mcp_kymograph.authorization import Declaration
from mcp_kymograph.driver import (
    MAX_PAGES,
    CallStep,
    ClientChannel,
    Driver,
    Script,
    Step,
    _ProbeContext,
    probe_script,
    run_driven,
)
from mcp_kymograph.engine import Engine
from mcp_kymograph.guard import ClientWriter, GuardedWriter, ScopeGuard
from mcp_kymograph.http_proxy import HttpProxy
from mcp_kymograph.masking import Masker
from mcp_kymograph.probes import MAX_CALLS, PROBES, Context, Probe, ProbeEnded, ProbeError
from mcp_kymograph.proxy import Limits, Proxy
from mcp_kymograph.recorder import Recorder
from mcp_kymograph.store import Store
from test_engagement import refused, write
from test_fleet import PINS, pair
from test_fleet_endpoint import with_endpoints
from test_fleet_engagement import NOW, engagement_file, launcher_under
from test_http_proxy import Stub, exchange_raw, reference_answer
from test_scope_guard import DISCOVERY, call, driven, leaks, parts_of, second, token

FIXTURES = Path(__file__).parent / "fixtures"
TOY = str(FIXTURES / "toy_server.py")


@pytest.fixture(autouse=True)
def salt(monkeypatch):
    """The file names ``salt_env: KYMOGRAPH_SALT``, and the gate refuses a run without a salt."""
    monkeypatch.setenv("KYMOGRAPH_SALT", "salt-" + secrets.token_hex(16))


#: Records every byte the server is sent into the file named first and, the first time one of
#: them is a ``tools/list``, creates the file named second (the stop file, or the flag of the
#: clock) before the bytes go on. It writes the pids of itself and of the server to the third.
LAUNCHER = f"""\
import os, subprocess, sys
log = open(sys.argv[1], "ab", buffering=0)
trigger = sys.argv[2]
child = subprocess.Popen([sys.executable, {DISCOVERY!r}, *sys.argv[4:]], stdin=subprocess.PIPE)
open(sys.argv[3], "w").write(f"{{os.getpid()}} {{child.pid}}")
fired = False
while True:
    chunk = sys.stdin.buffer.read1(65536)
    if not chunk:
        break
    if not fired and b'"tools/list"' in chunk and trigger != "-":
        fired = True
        open(trigger, "w").close()
    log.write(chunk)
    child.stdin.write(chunk)
    child.stdin.flush()
child.stdin.close()
sys.exit(child.wait())
"""

LIMITS = Limits(max_duration_seconds=60.0, terminate_grace_seconds=0.5, shutdown_budget_seconds=3.0)

#: Served by the fixture next to ``read``: a tool the engagement does not list.
OUTSIDE = "tool_0_1"


def probing(**changes) -> dict:
    """The file of test_scope_guard.second(), which lists the module ``echo``, with ``changes``."""
    data = second()
    data["actions"] = {"list": True, "call": True, "probes": ["echo"]}
    data.update(changes)
    return data


def engaged(tmp_path: Path, **changes) -> engagement.Engagement:
    (tmp_path / "engagement").mkdir(exist_ok=True)
    return engagement.load(write(tmp_path / "engagement", probing(**changes)))


class Clock:
    """The wall clock of a run: inside the window until the flag file is there."""

    def __init__(self, loaded: engagement.Engagement, flag: Path) -> None:
        self._until = loaded.window_until
        self._flag = flag

    def __call__(self) -> datetime:
        if self._flag.exists():
            return self._until + timedelta(minutes=1)
        return self._until - timedelta(hours=1)


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def of_type(recorded: list[dict], kind: str) -> list[dict]:
    return [e for e in recorded if e["type"] == kind]


def tool_calls_seen(log: Path) -> int:
    return log.read_bytes().count(b'"tools/call"') if log.exists() else 0


def gone(pid: int) -> bool:
    """Whether no process of that pid is left (a zombie is gone: nothing runs)."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class Driven:
    def __init__(self, tmp_path: Path) -> None:
        self.dir = tmp_path
        self.log = tmp_path / "server.log"
        self.pids = tmp_path / "pids"
        self.path = tmp_path / "events.jsonl"
        self.outcome = None
        self.run = None
        self.recorded: list[dict] = []

    def server_pids(self) -> list[int]:
        return [int(pid) for pid in self.pids.read_text().split()]


def drive(
    tmp_path: Path,
    loaded: engagement.Engagement | None,
    *,
    script: Script | None = None,
    probe: Probe | None = None,
    options: Mapping[str, str] | None = None,
    trigger: Path | None = None,
    clock=None,
    tools: tuple[str, ...] = ("--tool-name", "read", "--tool-count", "2"),
    engine: Engine | None = None,
    after_call=None,
    call_result: str = "text",
) -> Driven:
    """One driven run with a Driver and a Proxy built as ``cli`` builds them, a stop file or
    window that the server's first ``tools/list`` sets off, and the recording read back.
    ``engine`` is the scenario of the proxy; ``after_call(proxy)`` runs once the first call's
    step is recorded, so that a stop falls between that step and the next."""
    seen = Driven(tmp_path)
    launcher = tmp_path / "launcher.py"
    launcher.write_text(LAUNCHER)
    script = script or probe_script(probe)
    stop_check = None if loaded is None else (lambda: engagement.stopped(loaded))
    declaration = (
        Declaration() if loaded is None else Declaration(**engagement.declaration_fields(loaded))
    )

    async def go() -> None:
        channel = ClientChannel()
        try:
            with Recorder.open(seen.path, run_id="probe", masker=Masker()) as recorder:
                proxy = Proxy(
                    argv=[
                        sys.executable,
                        str(launcher),
                        str(seen.log),
                        "-" if trigger is None else str(trigger),
                        str(seen.pids),
                        *tools,
                        "--call-result",
                        call_result,
                    ],
                    recorder=recorder,
                    limits=LIMITS,
                    client_in=channel.proxy_in,
                    client_out=channel.proxy_out,
                    mode=events.Mode.DRIVER,
                    script=script.name,
                    declaration=declaration,
                    clock=clock,
                    stop_check=stop_check,
                    engine=engine,
                )
                record_called = proxy.record_step_called
                if after_call is not None:

                    async def record_called(**fields) -> None:
                        await proxy.record_step_called(**fields)
                        after_call(proxy)

                driver = Driver(
                    script,
                    channel,
                    record_skipped=proxy.record_step_skipped,
                    record_failed=proxy.record_server_failed,
                    record_unanswered=proxy.record_step_unanswered,
                    record_finished=proxy.record_script_finished,
                    record_called=record_called,
                    record_call_failed=proxy.record_call_failed,
                    record_blocked=proxy.record_call_blocked,
                    guard=None if loaded is None else ScopeGuard.of(loaded),
                    halt=proxy.halt_reason,
                    stop=proxy.stop_run,
                    probe=probe,
                    probe_options=options,
                    step_timeout=5,
                )
                seen.run = await asyncio.wait_for(run_driven(proxy, driver), 40)
                seen.outcome = driver.outcome
        finally:
            channel.close()

    asyncio.run(go())
    seen.recorded = events_of(seen.path)
    return seen


def two_calls() -> Script:
    return Script(
        name="two-calls",
        protocol_version="2025-06-18",
        client_info={"name": "t", "version": "0"},
        capabilities={},
        steps=(
            Step("tools/list", requires="tools", paginate=True),
            CallStep(tool="read", arguments={"text": "one"}),
            CallStep(tool="read", arguments={"text": "two"}),
            Step("tools/list", requires="tools", paginate=True),
        ),
    )


def stops(recorded: list[dict]) -> list[tuple[str, str]]:
    return [(e["signal"], e["because"]) for e in of_type(recorded, "run_stopped")]


# -- the reader and the stop file itself ----------------------------------------------------


def test_actions_probes_lists_module_names_and_is_empty_without_it(tmp_path):
    assert engaged(tmp_path).actions_probes == ("echo",)
    plain = engagement.load(write(tmp_path, {**probing(), "actions": {"list": True, "call": True}}))
    assert plain.actions_probes == ()


@pytest.mark.parametrize(
    ("listed", "words"),
    [
        ("echo", "expected a list"),
        ([5], "actions.probes[0]: expected a module name"),
        (["Echo"], "actions.probes[0]: expected a module name"),
        (["echo", "echo"], "actions.probes[1]: listed twice"),
    ],
)
def test_actions_probes_that_is_not_a_list_of_module_names_is_refused_with_its_place(
    tmp_path, listed, words
):
    data = probing()
    data["actions"]["probes"] = listed
    assert words in str(refused(tmp_path, data))


def test_in_a_file_of_the_first_version_probes_is_an_unknown_key(tmp_path):
    data = {"version": 1, "id": "a", "customer": "c", "window": {}, "targets": []}
    from test_engagement import base

    data = base()
    data["actions"]["probes"] = ["echo"]
    assert "actions: unknown key" in str(refused(tmp_path, data))


def test_the_module_names_the_frame_and_the_file_agree_on():
    assert set(PROBES) == {"echo"}
    assert all(engagement.PROBE_NAME.fullmatch(name) for name in PROBES)
    from mcp_kymograph.probes import base

    assert engagement.PROBE_NAME.pattern == base.NAME.pattern


def test_the_stop_file_is_named_after_the_engagement_file_and_made_when_it_is_read(tmp_path):
    loaded = engaged(tmp_path)
    expected = tmp_path / "engagement" / "engagement.json.stop"
    assert loaded.stop_file == str(expected) == str(engagement.stop_path(loaded.source))
    assert not engagement.stopped(loaded)
    assert engagement.stopped(None) is False


def test_the_stop_file_is_looked_for_and_never_read(tmp_path):
    path = tmp_path / "f.stop"
    assert engagement.stop_file_present(path) is False
    assert engagement.stop_file_present(None) is False
    path.write_text("not even JSON \xff")
    path.chmod(0)  # unreadable, and still there
    assert engagement.stop_file_present(path) is True
    path.unlink()
    (tmp_path / "dir.stop").mkdir()
    assert engagement.stop_file_present(tmp_path / "dir.stop") is True
    (tmp_path / "dangling.stop").symlink_to(tmp_path / "nowhere")
    assert engagement.stop_file_present(tmp_path / "dangling.stop") is True
    (tmp_path / "link.stop").symlink_to(tmp_path / "dir.stop")
    assert engagement.stop_file_present(tmp_path / "link.stop") is True


def test_a_path_that_cannot_be_looked_at_stops_the_run(tmp_path, monkeypatch):
    def broken(path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(os, "lstat", broken)
    assert engagement.stop_file_present(tmp_path / "x.stop") is True


# -- engagement stop -------------------------------------------------------------------------


def stop_command(loaded_path: Path, *extra: str) -> int:
    return cli.main(["engagement", "stop", str(loaded_path), *extra])


def test_engagement_stop_writes_the_file_beside_the_engagement_with_mode_0600(tmp_path):
    loaded = engaged(tmp_path)
    assert stop_command(Path(loaded.source), "--reason", "customer asked") == 0
    path = Path(loaded.stop_file)
    assert path.name == "engagement.json.stop" and path.parent == Path(loaded.source).parent
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    written = json.loads(path.read_text())
    assert written["reason"] == "customer asked"
    moment = datetime.fromisoformat(written["time"].replace("Z", "+00:00"))
    assert abs(datetime.now(timezone.utc) - moment) < timedelta(seconds=30)
    assert engagement.stopped(loaded)


def test_the_reason_is_cut_and_masked_like_other_text_the_operator_typed(tmp_path):
    loaded = engaged(tmp_path, redaction={"mask_keys": ["customer_id"]})
    secret = "Bearer " + "Ab1Cd2Ef3Gh4" * 3
    reason = f"customer_id=99887766 {secret} " + "x" * 400
    assert stop_command(Path(loaded.source), "--reason", reason) == 0
    kept = json.loads(Path(loaded.stop_file).read_text())["reason"]
    assert len(kept) <= engagement.MAX_STOP_REASON + 40
    assert secret not in kept and "99887766" not in kept
    assert engagement.MAX_STOP_REASON == 200


def test_a_token_the_cut_would_have_clipped_is_masked_before_the_cut(tmp_path):
    loaded = engaged(tmp_path)
    # Invented, and put together when the test runs so that no scanner finds it written out here.
    token = "".join(("Qx7R", "t5Wz3", "Lm9P", "v2Kd4", "Hs8Jn6"))
    # 186 characters, then the token: cut first, fewer than 8 of its characters would be left
    # and the rule for a bearer token would no longer know it
    reason = "x" * 186 + " Bearer " + token
    assert stop_command(Path(loaded.source), "--reason", reason) == 0
    text = Path(loaded.stop_file).read_text()
    assert not any(token[i : i + 3] in text for i in range(len(token) - 2))
    assert len(json.loads(text)["reason"]) <= engagement.MAX_STOP_REASON


def test_a_stop_file_that_is_there_is_made_again_with_the_new_reason(tmp_path):
    loaded = engaged(tmp_path)
    assert stop_command(Path(loaded.source), "--reason", "one") == 0
    assert stop_command(Path(loaded.source), "--reason", "two") == 0
    assert json.loads(Path(loaded.stop_file).read_text())["reason"] == "two"
    # the engagement, its scenarios, the stop file: no temporary file of the replacing
    names = sorted(p.name for p in Path(loaded.source).parent.iterdir())
    assert names == sorted([Path(loaded.source).name, "scenarios", Path(loaded.stop_file).name])


def test_engagement_stop_clear_removes_it_and_without_one_says_so_with_exit_0(tmp_path, capsys):
    loaded = engaged(tmp_path)
    capsys.readouterr()
    assert stop_command(Path(loaded.source), "--clear") == 0
    assert "there is no stop file" in capsys.readouterr().err
    stop_command(Path(loaded.source))
    assert stop_command(Path(loaded.source), "--clear") == 0
    assert not Path(loaded.stop_file).exists()
    assert not engagement.stopped(loaded)


def test_engagement_stop_refuses_a_file_that_is_not_there_and_clear_with_a_reason(tmp_path):
    assert stop_command(tmp_path / "nowhere.json") == 2
    loaded = engaged(tmp_path)
    assert stop_command(Path(loaded.source), "--clear", "--reason", "x") == 2


def test_engagement_stop_stops_even_a_file_that_cannot_be_read(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{ not an engagement")
    assert stop_command(broken, "--reason", "draft gone wrong") == 0
    assert (tmp_path / "broken.json.stop").exists()


# -- the gate -------------------------------------------------------------------------------

#: A script of one call and a probe, as a run under the file asks for them.
RUNS = {
    "script": [],
    "probe": ["--probe", "echo", "--probe-option", "tool=read"],
}


def cli_drive(tmp_path: Path, loaded, *extra: str, served: tuple[str, ...] = ()) -> int:
    args = ["drive", "--out-dir", str(tmp_path / "runs"), "-q"]
    if loaded is not None:
        args += ["--engagement", loaded.source]
    return cli.main(
        [
            *args,
            *extra,
            "--",
            sys.executable,
            DISCOVERY,
            "--tool-name",
            "read",
            "--tool-count",
            "2",
            "--call-result",
            "text",
            *served,
        ]
    )


@pytest.fixture
def nothing_starts(monkeypatch):
    started = []

    async def must_not_run(*args, **kwargs):
        started.append(args)
        raise AssertionError("a process was started although the run was refused")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)
    return started


def refusals(tmp_path: Path) -> list[str]:
    return [r.reason for r in engagement.read_refusals(tmp_path / "runs" / "refusals.jsonl")]


def test_probe_without_an_engagement_is_refused(tmp_path, nothing_starts, capsys):
    code = cli_drive(tmp_path, None, "--probe", "echo", "--probe-option", "tool=read")
    assert code == 2
    assert nothing_starts == []
    assert "give --engagement" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists() or not list((tmp_path / "runs").iterdir())


def test_a_module_the_file_does_not_list_is_refused_and_written_down(
    tmp_path, nothing_starts, capsys
):
    loaded = engaged(tmp_path, actions={"list": True, "call": True})
    code = cli_drive(tmp_path, loaded, *RUNS["probe"])
    assert code == 2 and nothing_starts == []
    assert ": probe_not_listed: " in capsys.readouterr().err
    assert refusals(tmp_path) == ["probe_not_listed"]
    assert [p for p in (tmp_path / "runs").iterdir() if p.is_dir()] == []


def test_a_module_listed_in_the_file_but_unknown_to_the_tool_is_refused_by_name(
    tmp_path, nothing_starts, capsys
):
    loaded = engaged(tmp_path, actions={"list": True, "call": True, "probes": ["flood"]})
    assert cli_drive(tmp_path, loaded, "--probe", "flood") == 2
    assert "is not a probe module" in capsys.readouterr().err
    assert refusals(tmp_path) == ["arguments"]


def test_probe_and_script_together_are_refused(tmp_path, nothing_starts, capsys):
    loaded = engaged(tmp_path)
    code = cli_drive(tmp_path, loaded, *RUNS["probe"], "--script", "discovery")
    assert code == 2 and nothing_starts == []
    assert "--probe and --script" in capsys.readouterr().err
    assert refusals(tmp_path) == ["arguments"]


@pytest.mark.parametrize(
    ("options", "words"),
    [
        ([], "needs the option tool"),
        (["tool=read", "colour=blue"], "takes no option 'colour'"),
        (["tool"], "--probe-option is a key, an equals sign and a value"),
        (["tool=read", "tool=write"], "given twice"),
        (["tool=" + "x" * 2000], "longer than"),
    ],
)
def test_options_a_module_does_not_take_are_refused(
    tmp_path, nothing_starts, capsys, options, words
):
    loaded = engaged(tmp_path)
    extra = [x for option in options for x in ("--probe-option", option)]
    assert cli_drive(tmp_path, loaded, "--probe", "echo", *extra) == 2
    assert words in capsys.readouterr().err
    assert refusals(tmp_path) == ["arguments"]


def test_a_token_in_the_words_of_a_refusal_is_masked_before_it_is_cut(
    tmp_path, nothing_starts, capsys
):
    """The words of a refusal name a value the operator or a script gave. Cut first, a token
    would be split and no longer recognised; masked first, no part of it is left on the terminal
    or in refusals.jsonl."""
    loaded = engaged(tmp_path)
    secret = token()
    cases = [
        # The token starts at character 20: with the old cut at 40, 20 of its characters stood.
        ["--probe", "a" * 19 + "/" + secret],
        # Given twice: that is the refusal which shows the key, cut at 40 in the old code.
        ["--probe", "echo", *["--probe-option", "a" * 19 + "/" + secret + "=x"] * 2],
    ]
    for extra in cases:
        assert cli_drive(tmp_path, loaded, *extra) == 2
    (tmp_path / "script").mkdir()
    # A script's tool name is at most 128 characters, so no token in it is split by a cut; the
    # whole of it is on the terminal unless the words are masked there.
    code, out = driven(tmp_path / "script", "a" * 80 + "/" + secret, served="read")
    assert code == 2
    shown = capsys.readouterr()
    written = (tmp_path / "runs" / "refusals.jsonl").read_text()
    assert len(written.splitlines()) == 2
    assert not leaks(secret, shown.out, shown.err, written)
    assert not leaks(secret, (out / "refusals.jsonl").read_text())


def test_the_words_of_a_refusal_are_cut_in_the_file_after_the_masking(tmp_path, nothing_starts):
    loaded = engaged(tmp_path)
    assert cli_drive(tmp_path, loaded, "--probe", "x" * 5000) == 2
    (record,) = engagement.read_refusals(tmp_path / "runs" / "refusals.jsonl")
    assert len(record.message) == engagement.MAX_REFUSAL_MESSAGE


def test_record_refusal_masks_a_token_across_the_cut_before_cutting(tmp_path):
    loaded = engaged(tmp_path)
    secret = token()
    start = engagement.MAX_REFUSAL_MESSAGE - 10
    message = ("w " * start)[:start] + secret
    message += " z" * ((5000 - len(message)) // 2)
    assert len(message) >= 4990 and message.index(secret) == start
    assert start + len(secret) > engagement.MAX_REFUSAL_MESSAGE
    out = tmp_path / "runs"
    assert (
        engagement.record_refusal(
            out,
            argv=["drive"],
            masker=Masker(),
            reason="arguments",
            message=message,
            engagement=loaded,
            now=NOW,
        )
        is None
    )
    written = (out / engagement.REFUSALS_FILE).read_text()
    (record,) = engagement.read_refusals(out / engagement.REFUSALS_FILE)
    assert 0 < len(record.message) <= engagement.MAX_REFUSAL_MESSAGE
    assert not leaks(secret, written)


def test_a_fleet_refusal_under_a_file_masks_the_words_it_shows_and_writes(
    tmp_path, monkeypatch, capsys
):
    """The manifest's endpoint entry is named in the words of the fleet's refusal; a name that
    is a token is on neither the terminal nor refusals.jsonl."""

    def must_not_pin(*args, **kwargs):
        raise AssertionError("the images were pinned, which starts docker, before the refusal")

    monkeypatch.setattr(cli.fleet, "pin", must_not_pin)
    secret = token()
    manifest = with_endpoints(tmp_path, secret)
    loaded = engaged(tmp_path)
    out = tmp_path / "runs"
    code = cli.main(
        ["fleet", "run", "--manifest", str(manifest), "--store", str(tmp_path / "s.sqlite"),
         "--out-dir", str(out), "--engagement", loaded.source]
    )  # fmt: skip
    assert code == 2
    said = capsys.readouterr().err
    assert "endpoint entry" in said
    assert refusals(tmp_path) == ["fleet"]
    assert not leaks(secret, said, (out / engagement.REFUSALS_FILE).read_text())


def test_a_probe_option_without_a_probe_is_refused(tmp_path, nothing_starts):
    loaded = engaged(tmp_path)
    assert cli_drive(tmp_path, loaded, "--probe-option", "tool=read") == 2
    assert refusals(tmp_path) == ["arguments"]


def test_a_probe_acts_so_a_file_that_forbids_calls_refuses_it(tmp_path, nothing_starts):
    loaded = engaged(tmp_path, actions={"list": True, "call": False, "probes": ["echo"]})
    assert cli_drive(tmp_path, loaded, *RUNS["probe"]) == 2
    assert refusals(tmp_path) == ["calls_not_permitted"]


@pytest.mark.parametrize("kind", sorted(RUNS))
def test_a_stop_file_that_is_there_refuses_the_run_at_the_gate(
    tmp_path, nothing_starts, capsys, kind
):
    loaded = engaged(tmp_path)
    assert stop_command(Path(loaded.source), "--reason", "stop") == 0
    capsys.readouterr()
    assert cli_drive(tmp_path, loaded, *RUNS[kind]) == 2
    assert nothing_starts == []
    assert ": stop_file: " in capsys.readouterr().err
    assert refusals(tmp_path) == ["stop_file"]
    assert [p for p in (tmp_path / "runs").iterdir() if p.is_dir()] == []


def test_a_stop_file_refuses_a_run_of_the_proxy_too(tmp_path, nothing_starts, capsys):
    loaded = engaged(tmp_path)
    stop_command(Path(loaded.source))
    code = cli.main(
        [
            "run",
            "--engagement",
            loaded.source,
            "--out-dir",
            str(tmp_path / "runs"),
            "--",
            sys.executable,
            TOY,
        ]  # fmt: skip
    )
    assert code == 2 and nothing_starts == []
    assert refusals(tmp_path) == ["stop_file"]


def test_after_the_stop_file_is_cleared_the_same_run_goes_through(tmp_path):
    loaded = engaged(tmp_path)
    stop_command(Path(loaded.source))
    assert cli_drive(tmp_path, loaded, *RUNS["probe"]) == 2
    stop_command(Path(loaded.source), "--clear")
    assert cli_drive(tmp_path, loaded, *RUNS["probe"]) == 0


# -- one stop file for every path to the engagement file ----------------------------------------


def alias_of_the_file(tmp_path: Path, form: str) -> tuple[Path, Path]:
    """The engagement file's real path, and another path to the same file: a symlink to the
    file, a symlink to its directory, or a relative path (the caller changes directory)."""
    real = Path(engaged(tmp_path).source)
    if form == "file":
        alias = tmp_path / "link.json"
        alias.symlink_to(real)
    elif form == "directory":
        (tmp_path / "linked").symlink_to(real.parent, target_is_directory=True)
        alias = tmp_path / "linked" / real.name
    else:
        alias = Path(os.path.relpath(real, tmp_path))
    return real, alias


@pytest.mark.parametrize("form", ["file", "directory", "relative"])
def test_a_run_loaded_by_a_link_is_stopped_by_the_real_path(
    tmp_path, nothing_starts, capsys, monkeypatch, form
):
    real, alias = alias_of_the_file(tmp_path, form)
    monkeypatch.chdir(tmp_path)
    loaded = engagement.load(alias)
    assert loaded.stop_file == str(real.resolve()) + engagement.STOP_SUFFIX
    assert not engagement.stopped(loaded)
    assert stop_command(real, "--reason", "stop") == 0
    assert engagement.stopped(loaded)
    capsys.readouterr()
    assert cli_drive(tmp_path, loaded, *RUNS["script"]) == 2
    assert nothing_starts == []
    assert refusals(tmp_path) == ["stop_file"]


@pytest.mark.parametrize("form", ["file", "directory", "relative"])
def test_a_run_loaded_by_the_real_path_is_stopped_by_a_link(
    tmp_path, nothing_starts, capsys, monkeypatch, form
):
    real, alias = alias_of_the_file(tmp_path, form)
    monkeypatch.chdir(tmp_path)
    loaded = engagement.load(real)
    assert stop_command(alias, "--reason", "stop") == 0
    assert Path(loaded.stop_file).exists() and engagement.stopped(loaded)
    assert not list(tmp_path.rglob("link.json.stop"))
    capsys.readouterr()
    assert cli_drive(tmp_path, loaded, *RUNS["script"]) == 2
    assert nothing_starts == []
    assert refusals(tmp_path) == ["stop_file"]


@pytest.mark.parametrize("form", ["file", "directory", "relative"])
def test_clear_by_the_other_path_lifts_the_stop(tmp_path, monkeypatch, form):
    real, alias = alias_of_the_file(tmp_path, form)
    monkeypatch.chdir(tmp_path)
    loaded = engagement.load(real)
    assert stop_command(real) == 0 and engagement.stopped(loaded)
    assert stop_command(alias, "--clear") == 0
    assert not engagement.stopped(loaded)
    assert stop_command(alias) == 0 and engagement.stopped(loaded)
    assert stop_command(real, "--clear") == 0
    assert not engagement.stopped(loaded)


def repointed_link(tmp_path: Path) -> tuple[Path, Path]:
    """``current`` links to ``release-1`` holding the engagement file; a run is loaded by
    ``current/…``, then ``current`` is pointed at ``release-2``, which holds a copy. Returns the
    path through the link and the copy's real path."""
    first, second = tmp_path / "release-1", tmp_path / "release-2"
    for release in (first, second):
        release.mkdir()
        write(release, probing())
    current = tmp_path / "current"
    current.symlink_to(first, target_is_directory=True)
    return current / "engagement.json", second / "engagement.json"


def point_elsewhere(tmp_path: Path) -> None:
    (tmp_path / "current").unlink()
    (tmp_path / "current").symlink_to(tmp_path / "release-2", target_is_directory=True)


def test_a_run_loaded_through_a_link_that_is_repointed_is_stopped_by_the_new_target(tmp_path):
    through, second = repointed_link(tmp_path)
    loaded = engagement.load(through)
    assert loaded.stop_file_as_given == str(through) + engagement.STOP_SUFFIX
    point_elsewhere(tmp_path)
    assert not engagement.stopped(loaded)
    assert stop_command(through, "--reason", "stop") == 0
    assert Path(str(second) + engagement.STOP_SUFFIX).exists()
    assert not Path(loaded.stop_file).exists()
    assert engagement.stopped(loaded)
    assert stop_command(through, "--clear") == 0
    assert not engagement.stopped(loaded)


def test_a_driven_run_loaded_through_a_repointed_link_is_stopped(tmp_path):
    through, _ = repointed_link(tmp_path)
    loaded = engagement.load(through)
    point_elsewhere(tmp_path)
    assert not engagement.stopped(loaded)  # what cli hands the Proxy and the Driver asks
    assert stop_command(through) == 0
    assert engagement.stopped(loaded)


def test_a_fleet_loaded_through_a_repointed_link_is_refused_when_stopped(tmp_path):
    through, _ = repointed_link(tmp_path)
    loaded = engagement.load(through)
    point_elsewhere(tmp_path)
    stop_command(through)
    launch = launcher_under(loaded.digest)
    with Store.open(tmp_path / "s.sqlite") as store, pytest.raises(fleet.FleetError) as refusal:
        fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launch,
                  engagement=loaded, now=NOW)  # fmt: skip
    assert refusal.value.condition == "stop_file"
    assert launch.handed == []


def linked_file(tmp_path: Path, releases: int = 2) -> tuple[Path, list[Path]]:
    """``current.json`` links to the file itself in ``release-1``; each of the other releases
    holds a copy. Returns the link and the copies' real paths, the first the one it points to."""
    files = []
    for number in range(1, releases + 1):
        release = tmp_path / f"release-{number}"
        release.mkdir()
        files.append(write(release, probing()))
    link = tmp_path / "current.json"
    link.symlink_to(files[0])
    return link, files


def point_file_at(link: Path, target: Path) -> None:
    link.unlink()
    link.symlink_to(target)


def test_a_run_loaded_through_a_link_to_the_file_that_is_repointed_is_stopped(tmp_path):
    link, (first, second) = linked_file(tmp_path)
    loaded = engagement.load(link)
    assert loaded.stop_file == str(first.resolve()) + engagement.STOP_SUFFIX
    point_file_at(link, second)
    assert not engagement.stopped(loaded)
    assert stop_command(link, "--reason", "stop") == 0
    assert Path(str(second) + engagement.STOP_SUFFIX).exists()
    assert not Path(loaded.stop_file).exists()
    assert not Path(loaded.stop_file_as_given).exists()
    assert engagement.stopped(loaded)


def test_a_link_to_the_file_repointed_twice_is_still_stopped_by_the_link(tmp_path):
    link, (first, second, third) = linked_file(tmp_path, 3)
    loaded = engagement.load(link)
    point_file_at(link, second)
    point_file_at(link, third)
    assert not engagement.stopped(loaded)
    assert stop_command(link) == 0
    assert Path(str(third) + engagement.STOP_SUFFIX).exists()
    assert engagement.stopped(loaded)


def test_clear_through_the_repointed_link_to_the_file_lifts_the_stop(tmp_path):
    link, (first, second) = linked_file(tmp_path)
    loaded = engagement.load(link)
    point_file_at(link, second)
    assert stop_command(link) == 0 and engagement.stopped(loaded)
    assert stop_command(link, "--clear") == 0
    assert not engagement.stopped(loaded)
    assert not list(tmp_path.rglob("*" + engagement.STOP_SUFFIX))


def test_a_loop_in_the_link_stops_the_run_without_a_traceback(tmp_path):
    link, _ = linked_file(tmp_path)
    loaded = engagement.load(link)
    other = tmp_path / "b.json"
    link.unlink()
    link.symlink_to(other)
    other.symlink_to(link)
    assert engagement.stopped(loaded)
    assert engagement.stop_file_resolved_now(loaded.stop_file_as_given)


def test_a_name_that_cannot_be_resolved_is_told_from_one_that_is_gone(tmp_path, monkeypatch):
    link, _ = linked_file(tmp_path)
    loaded = engagement.load(link)
    link.unlink()  # the file is gone: no stop by this name
    assert not engagement.stopped(loaded)
    assert not engagement.stop_file_resolved_now(None)

    def refuse(*_args, **_kwargs):
        raise PermissionError(13, "no rights")

    monkeypatch.setattr(engagement.os.path, "realpath", refuse)
    assert engagement.stopped(loaded)


def test_a_name_that_is_too_long_stops_and_a_file_in_the_path_does_not(tmp_path):
    too_long = tmp_path / ("x" * 5000)
    assert engagement.stop_file_resolved_now(str(too_long) + engagement.STOP_SUFFIX)
    plain = tmp_path / "datei"
    plain.write_text("")
    below = plain / "kind"
    assert not engagement.stop_file_resolved_now(str(below) + engagement.STOP_SUFFIX)


def dotdot_link(tmp_path: Path) -> tuple[Path, Path]:
    """``current`` links to ``release-1/sub``; the engagement file lies in ``release-1``, a copy in
    ``release-2``. Returns ``current/../engagement.json`` and the copy's real path."""
    for number in (1, 2):
        release = tmp_path / f"release-{number}"
        (release / "sub").mkdir(parents=True)
        write(release, probing())
    (tmp_path / "current").symlink_to(tmp_path / "release-1" / "sub", target_is_directory=True)
    return (
        tmp_path / "current" / ".." / "engagement.json",
        tmp_path / "release-2" / "engagement.json",
    )


def point_dotdot_elsewhere(tmp_path: Path) -> None:
    (tmp_path / "current").unlink()
    (tmp_path / "current").symlink_to(tmp_path / "release-2" / "sub", target_is_directory=True)


def test_a_dotdot_behind_a_link_is_stopped_after_the_link_is_repointed(tmp_path):
    through, second = dotdot_link(tmp_path)
    loaded = engagement.load(through)
    point_dotdot_elsewhere(tmp_path)
    assert not engagement.stopped(loaded)
    assert stop_command(through, "--reason", "stop") == 0
    assert Path(str(second) + engagement.STOP_SUFFIX).exists()
    assert engagement.stopped(loaded)
    assert stop_command(through, "--clear") == 0
    assert not engagement.stopped(loaded)


def test_a_relative_dotdot_behind_a_link_is_stopped_from_another_directory(tmp_path, monkeypatch):
    through, second = dotdot_link(tmp_path)
    monkeypatch.chdir(tmp_path)
    loaded = engagement.load(Path("current") / ".." / "engagement.json")
    assert Path(loaded.stop_file_as_given).is_absolute()
    assert ".." in Path(loaded.stop_file_as_given).parts
    point_dotdot_elsewhere(tmp_path)
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert not engagement.stopped(loaded)
    assert stop_command(through) == 0
    assert Path(str(second) + engagement.STOP_SUFFIX).exists()
    assert engagement.stopped(loaded)


def test_an_absolute_path_is_loaded_without_asking_for_the_working_directory(tmp_path, monkeypatch):
    through, _ = dotdot_link(tmp_path)

    def gone():
        raise FileNotFoundError("working directory deleted")

    monkeypatch.setattr(os, "getcwd", gone)
    loaded = engagement.load(through)
    assert loaded.stop_file_as_given == str(through) + engagement.STOP_SUFFIX


def test_a_driven_run_and_a_proxy_through_a_repointed_link_to_the_file_are_stopped(tmp_path):
    link, (_, second) = linked_file(tmp_path)
    loaded = engagement.load(link)
    point_file_at(link, second)
    assert not engagement.stopped(loaded)  # what cli hands the Proxy and the Driver asks
    stop_command(link)
    assert engagement.stopped(loaded)


def test_a_fleet_loaded_through_a_repointed_link_to_the_file_is_refused_when_stopped(tmp_path):
    link, (_, second) = linked_file(tmp_path)
    loaded = engagement.load(link)
    point_file_at(link, second)
    stop_command(link)
    launch = launcher_under(loaded.digest)
    with Store.open(tmp_path / "s.sqlite") as store, pytest.raises(fleet.FleetError) as refusal:
        fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launch,
                  engagement=loaded, now=NOW)  # fmt: skip
    assert refusal.value.condition == "stop_file"
    assert launch.handed == []


# -- the descriptor, not the path ---------------------------------------------------------------


def test_the_stop_file_gets_its_mode_by_the_descriptor_and_never_by_the_path(tmp_path, monkeypatch):
    def by_path(*args, **kwargs):
        raise AssertionError("the mode was set by the path")

    monkeypatch.setattr(os, "chmod", by_path)
    path = tmp_path / "x.stop"
    before = os.umask(0o277)  # would leave 0400 if nothing but the open's mode counted
    try:
        engagement.write_stop_file(
            path, reason="r", masker=Masker(), now=datetime(2026, 11, 4, tzinfo=timezone.utc)
        )
    finally:
        os.umask(before)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def written(path: Path, reason: str) -> None:
    engagement.write_stop_file(
        path, reason=reason, masker=Masker(), now=datetime(2026, 11, 4, tzinfo=timezone.utc)
    )


def test_a_stop_file_with_a_name_of_the_longest_length_is_made_and_replaced(tmp_path):
    path = tmp_path / ("x" * 255)
    written(path, "first")
    written(path, "second")
    assert os.listdir(tmp_path) == [path.name]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["reason"] == "second"


def test_a_stop_file_is_replaced_in_one_step_and_is_there_at_every_moment(tmp_path, monkeypatch):
    path = tmp_path / "x.stop"
    written(path, "old")
    real = os.replace
    seen = []

    def replace(source, target):
        seen.append((Path(target) == path, json.loads(path.read_text())["reason"]))
        real(source, target)

    monkeypatch.setattr(os, "replace", replace)
    written(path, "new")
    assert seen == [(True, "old")], "the old file was at its place when the new one came"
    assert json.loads(path.read_text())["reason"] == "new"


def test_a_stop_file_that_cannot_be_replaced_stays_as_it_was_and_leaves_nothing_behind(
    tmp_path, monkeypatch
):
    path = tmp_path / "x.stop"
    written(path, "old")
    before = path.read_bytes()

    def broken(source, target):
        raise OSError(5, "no")

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(OSError):
        written(path, "new")
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir()] == ["x.stop"]


def test_a_link_in_the_place_of_the_stop_file_is_replaced_and_not_written_through(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    path = tmp_path / "x.stop"
    path.symlink_to(target)
    written(path, "r")
    assert target.read_text() == "keep"
    assert not path.is_symlink() and path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_gate_checks_the_stop_file_it_is_told_of_and_the_module_it_is_told_of():
    from test_engagement import base

    loaded = engagement.loads(
        json.dumps(probing() | {"window": base()["window"]}).encode(),
        source="x.json",
        directory=Path("."),
    )
    now = datetime(2026, 10, 30, tzinfo=timezone.utc)
    facts = engagement.GateFacts(command="drive", script_lists=True, declared_target="127.0.0.1")
    engagement.check(loaded, facts, now)
    with pytest.raises(engagement.EngagementRefused) as stopped:
        engagement.check(loaded, dataclasses.replace(facts, stopped=True), now)
    assert stopped.value.condition == "stop_file"
    with pytest.raises(engagement.EngagementRefused) as unlisted:
        engagement.check(loaded, dataclasses.replace(facts, probe="flood"), now)
    assert unlisted.value.condition == "probe_not_listed"
    engagement.check(loaded, dataclasses.replace(facts, probe="echo"), now)


# -- the end of the window --------------------------------------------------------------------


def test_drive_script_ends_at_the_window_and_no_step_reaches_the_server_after_it(tmp_path):
    loaded = engaged(tmp_path)
    flag = tmp_path / "window-closed"
    seen = drive(tmp_path, loaded, script=two_calls(), trigger=flag, clock=Clock(loaded, flag))
    recorded = seen.recorded
    # the window closed as the first listing was sent: the listing was answered, no call went on
    assert tool_calls_seen(seen.log) == 0
    assert [e["reason"] for e in of_type(recorded, "step_skipped")] == ["run_halted"] * 3
    assert [e["step"] for e in of_type(recorded, "step_skipped")] == [
        "tools/call",
        "tools/call",
        "tools/list",
    ]
    assert of_type(recorded, "step_called") == []
    assert stops(recorded) == [("window_closed", "window_closed")]
    (finished,) = of_type(recorded, "run_finished")
    assert (finished["reason"], finished["window_exceeded"]) == ("window_closed", True)
    assert seen.run.stopped == "window_closed" and seen.outcome.halted == "window_closed"
    assert of_type(recorded, "server_exited") != []
    assert all(gone(pid) for pid in seen.server_pids())
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes


def test_drive_script_that_is_in_the_window_runs_every_step(tmp_path):
    loaded = engaged(tmp_path)
    seen = drive(
        tmp_path, loaded, script=two_calls(), trigger=None, clock=Clock(loaded, tmp_path / "x")
    )
    assert tool_calls_seen(seen.log) == 2
    assert of_type(seen.recorded, "run_stopped") == []
    (finished,) = of_type(seen.recorded, "run_finished")
    assert finished["window_exceeded"] is False and finished["reason"] != "window_closed"


def test_drive_probe_echo_ends_at_the_window_before_its_call(tmp_path):
    loaded = engaged(tmp_path)
    flag = tmp_path / "window-closed"
    seen = drive(
        tmp_path,
        loaded,
        probe=PROBES["echo"],
        options={"tool": "read", "text": "hi"},
        trigger=flag,
        clock=Clock(loaded, flag),
    )
    assert tool_calls_seen(seen.log) == 0
    assert of_type(seen.recorded, "step_called") == []
    (skipped,) = of_type(seen.recorded, "step_skipped")
    assert (skipped["step"], skipped["reason"]) == ("tools/call", "run_halted")
    (finished,) = of_type(seen.recorded, "run_finished")
    assert (finished["reason"], finished["window_exceeded"]) == ("window_closed", True)
    assert all(gone(pid) for pid in seen.server_pids())


def test_through_the_command_line_a_drive_probe_ends_at_the_window(tmp_path, monkeypatch):
    """The wiring of ``cli``: the proxy it builds has a clock, and the driver asks it."""
    loaded = engaged(tmp_path)
    flag = tmp_path / "window-closed"
    clock = Clock(loaded, flag)

    class Clocked(cli._DrivenProxy):
        def __init__(self, **kwargs):
            super().__init__(clock=clock, **kwargs)

    monkeypatch.setattr(cli, "_DrivenProxy", Clocked)
    launcher = tmp_path / "launcher.py"
    launcher.write_text(LAUNCHER)
    code = cli.main(
        [
            "drive",
            "--engagement",
            loaded.source,
            "--out-dir",
            str(tmp_path / "runs"),
            "-q",
            "--probe",
            "echo",
            "--probe-option",
            "tool=read",
            "--",
            sys.executable,
            str(launcher),
            str(tmp_path / "log"),
            str(flag),
            str(tmp_path / "pids"),
            "--tool-name",
            "read",
            "--call-result",
            "text",
        ]  # fmt: skip
    )
    (path,) = (tmp_path / "runs").glob("*/events.jsonl")
    recorded = events_of(path)
    assert code == 3
    assert tool_calls_seen(tmp_path / "log") == 0
    assert of_type(recorded, "run_finished")[0]["reason"] == "window_closed"
    assert verdict.read(path).state == verdict.INCOMPLETE


def stdio_session(tmp_path: Path, loaded, clock, *, then_more: bool):
    """A proxied session (nobody drives it): one request, its answer, the clock passes the
    window's end, one more request — which a passive run still passes on and records."""

    async def go():
        to_proxy_read, to_proxy = os.pipe()
        from_proxy, from_proxy_write = os.pipe()
        client_in = os.fdopen(to_proxy_read, "rb", buffering=0)
        client_out = os.fdopen(from_proxy_write, "wb", buffering=0)
        received = os.fdopen(from_proxy, "rb", buffering=0)
        path = tmp_path / "events.jsonl"
        with Recorder.open(path, run_id="passive", masker=Masker()) as recorder:
            proxy = Proxy(
                argv=[sys.executable, TOY, "--mode", "normal"],
                recorder=recorder,
                limits=LIMITS,
                client_in=client_in,
                client_out=client_out,
                declaration=Declaration(**engagement.declaration_fields(loaded)),
                clock=clock,
                guard=ScopeGuard.of(loaded),
            )
            task = asyncio.create_task(proxy.run())
            ask = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
            os.write(to_proxy, ask)
            first = await asyncio.wait_for(asyncio.to_thread(received.readline), 10)
            assert json.loads(first)["id"] == 1
            clock.flag.touch()
            answer = None
            if then_more:
                os.write(to_proxy, ask.replace(b'"id": 1', b'"id": 2'))
                answer = await asyncio.wait_for(asyncio.to_thread(received.readline), 10)
            os.close(to_proxy)
            outcome = await asyncio.wait_for(task, 20)
        for handle in (client_in, client_out, received):
            with contextlib.suppress(OSError):
                handle.close()
        return outcome, answer, path

    return asyncio.run(go())


def test_a_passive_run_goes_on_recording_after_the_window_and_only_notes_it(tmp_path):
    loaded = engaged(tmp_path)
    flag = tmp_path / "window-closed"
    clock = Clock(loaded, flag)
    clock.flag = flag
    outcome, answer, path = stdio_session(tmp_path, loaded, clock, then_more=True)
    assert json.loads(answer)["id"] == 2, "a message after the window's end is still passed on"
    recorded = events_of(path)
    (finished,) = of_type(recorded, "run_finished")
    assert finished["window_exceeded"] is True
    assert finished["reason"] != "window_closed" and outcome.stopped is None
    assert of_type(recorded, "run_stopped") == []
    answered = [e for e in of_type(recorded, "message") if e["direction"] == "server_to_client"]
    assert len(answered) == 2, "both answers are in the recording"


def test_the_guard_of_a_passive_run_blocks_nothing_for_the_window(tmp_path):
    loaded = engaged(tmp_path)
    flag = tmp_path / "window-closed"
    flag.touch()  # closed from the start
    clock = Clock(loaded, flag)
    clock.flag = flag
    _, answer, path = stdio_session(tmp_path, loaded, clock, then_more=True)
    assert json.loads(answer)["id"] == 2
    assert of_type(events_of(path), "call_blocked") == []


# -- the stop file during a run --------------------------------------------------------------


def test_drive_script_stops_before_the_next_step_when_the_stop_file_appears(tmp_path):
    loaded = engaged(tmp_path)
    seen = drive(tmp_path, loaded, script=two_calls(), trigger=Path(loaded.stop_file))
    recorded = seen.recorded
    assert tool_calls_seen(seen.log) == 0
    assert [e["reason"] for e in of_type(recorded, "step_skipped")] == ["run_halted"] * 3
    assert stops(recorded) == [("stop_file", "stop_file")]
    (finished,) = of_type(recorded, "run_finished")
    assert finished["reason"] == "stop_file" and finished["window_exceeded"] is False
    assert seen.outcome.halted == "stop_file"
    assert all(gone(pid) for pid in seen.server_pids())
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes


def test_drive_probe_stops_before_its_call_when_the_stop_file_appears(tmp_path):
    loaded = engaged(tmp_path)
    seen = drive(
        tmp_path,
        loaded,
        probe=PROBES["echo"],
        options={"tool": "read"},
        trigger=Path(loaded.stop_file),
    )
    assert tool_calls_seen(seen.log) == 0
    assert of_type(seen.recorded, "step_called") == []
    assert [e["reason"] for e in of_type(seen.recorded, "step_skipped")] == ["run_halted"]
    assert stops(seen.recorded) == [("stop_file", "stop_file")]


def test_a_stop_file_does_not_hold_a_driver_without_an_engagement_to_anything(tmp_path):
    seen = drive(tmp_path, None, script=two_calls(), trigger=None)
    assert tool_calls_seen(seen.log) == 2 and seen.outcome.halted is None


class OnClient:
    """A rule that sees the client's direction and changes nothing: it puts that direction on
    the message-by-message path."""

    name = "on-client"
    directions = frozenset({events.Direction.CLIENT_TO_SERVER})

    def act(self, direction, document, responded_method):
        return None


async def proxied(
    tmp_path: Path,
    loaded,
    *,
    send_after_stop: bytes | None = None,
    unfinished: bytes | None = None,
    stop: bool = True,
    cleared: bool = False,
    guarded: bool = False,
    engine: Engine | None = None,
):
    """A stdio proxy with a silent client; the stop file appears; what the run did.

    With ``unfinished`` the client sends that, without a newline, once the proxy has read it, and
    then ends its input (after the stop file, if there is to be one). With ``cleared`` the stop
    file is removed once the proxy has seen it, before the client sends more."""
    to_proxy_read, to_proxy = os.pipe()
    from_proxy, from_proxy_write = os.pipe()
    client_in = os.fdopen(to_proxy_read, "rb", buffering=0)
    client_out = os.fdopen(from_proxy_write, "wb", buffering=0)
    received = os.fdopen(from_proxy, "rb", buffering=0)
    log = tmp_path / "server.log"
    launcher = tmp_path / "launcher.py"
    launcher.write_text(LAUNCHER)
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="passive", masker=Masker()) as recorder:
        proxy = Proxy(
            argv=[sys.executable, str(launcher), str(log), "-", str(tmp_path / "pids")],
            recorder=recorder,
            limits=LIMITS,
            client_in=client_in,
            client_out=client_out,
            declaration=Declaration(**engagement.declaration_fields(loaded)),
            stop_check=lambda: engagement.stopped(loaded),
            guard=ScopeGuard.of(loaded) if guarded else None,
            engine=engine,
        )
        task = asyncio.create_task(proxy.run())
        ask = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
        os.write(to_proxy, ask)
        await asyncio.wait_for(asyncio.to_thread(received.readline), 10)
        if unfinished is not None:
            os.write(to_proxy, unfinished)
            while proxy._client_input_bytes < len(ask) + len(unfinished):
                await asyncio.sleep(0.01)
        if stop:
            Path(loaded.stop_file).write_text("{}")
        if cleared:
            while not proxy._stop_file_seen:
                await asyncio.sleep(0.01)
            Path(loaded.stop_file).unlink()
        if unfinished is not None:
            os.close(to_proxy)
        if send_after_stop is not None:
            os.write(to_proxy, send_after_stop)
        started = time.monotonic()
        outcome = await asyncio.wait_for(task, 20)
        took = time.monotonic() - started
    for handle in (client_in, client_out, received):
        with contextlib.suppress(OSError):
            handle.close()
    if unfinished is None:
        os.close(to_proxy)
    return outcome, took, path, log


def test_the_stdio_proxy_ends_in_order_when_the_stop_file_appears_and_the_client_is_silent(
    tmp_path,
):
    loaded = engaged(tmp_path)
    outcome, took, path, _ = asyncio.run(proxied(tmp_path, loaded))
    assert took < 4, "looked for at least once a second"
    recorded = events_of(path)
    assert (outcome.reason, outcome.stopped) == ("stop_file", "stop_file")
    assert stops(recorded) == [("stop_file", "stop_file")]
    assert of_type(recorded, "server_exited") != []
    (finished,) = of_type(recorded, "run_finished")
    assert finished["reason"] == "stop_file"
    pids = [int(pid) for pid in (tmp_path / "pids").read_text().split()]
    assert all(gone(pid) for pid in pids)
    judged = verdict.read(path)
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes


def test_the_stdio_proxy_passes_no_message_on_once_the_stop_file_is_there(tmp_path):
    loaded = engaged(tmp_path)
    more = b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    outcome, _, _, log = asyncio.run(proxied(tmp_path, loaded, send_after_stop=more))
    assert outcome.stopped == "stop_file"
    assert b"tools/list" not in log.read_bytes()


def test_the_stdio_proxy_passes_nothing_on_after_the_stop_file_that_it_saw_is_removed(tmp_path):
    loaded = engaged(tmp_path)
    more = b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    outcome, _, _, log = asyncio.run(proxied(tmp_path, loaded, send_after_stop=more, cleared=True))
    assert not Path(loaded.stop_file).exists()
    assert outcome.stopped == "stop_file"
    assert b"tools/list" not in log.read_bytes()


class Directed:
    """An observer of the client's direction that records what it is fed."""

    direction = events.Direction.CLIENT_TO_SERVER

    def __init__(self) -> None:
        self.fed: list[bytes] = []

    def observe(self, chunk: bytes) -> None:
        self.fed.append(chunk)

    def finish(self) -> None:
        pass


def test_the_stdio_pump_passes_nothing_on_after_the_stop_file_that_it_saw_is_removed(tmp_path):
    # The pump itself, not a run: in a run the proxy is already ending when the data would arrive,
    # and a request that is never read would say nothing about what the pump does with it.
    async def go():
        proxy, asked = stop_checked(tmp_path, [False] * 3)  # the file is gone now
        proxy._stop_file_seen = True  # it was there once
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
        reader.feed_eof()
        writer, observer = Written(), Directed()
        await proxy._pump(reader, writer, observer)
        return writer.chunks, observer.fed, asked

    assert asyncio.run(go()) == ([], [], []), "a request got through"


#: An allowed call whose line the client never ends.
UNFINISHED = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read"}}'


@pytest.mark.parametrize("engine", [None, "scenario"])
def test_a_line_unfinished_at_the_stop_does_not_go_on_to_the_server(tmp_path, engine):
    loaded = engaged(tmp_path)
    rules = Engine([OnClient()]) if engine else None
    outcome, _, path, log = asyncio.run(
        proxied(tmp_path, loaded, unfinished=UNFINISHED, guarded=True, engine=rules)
    )
    assert outcome.stopped == "stop_file"
    assert b"initialize" in log.read_bytes()
    assert b"tools/call" not in log.read_bytes()
    received = [
        e
        for e in of_type(events_of(path), "message")
        if e["direction"] == "client_to_server" and e["incomplete"]
    ]
    assert [e["payload"]["data"] for e in received] == [UNFINISHED.decode()], (
        "the line stands in the recording as received from the client"
    )


@pytest.mark.parametrize("engine", [None, "scenario"])
def test_a_line_unfinished_at_the_end_of_the_input_without_a_stop_goes_on(tmp_path, engine):
    loaded = engaged(tmp_path)
    rules = Engine([OnClient()]) if engine else None
    outcome, _, _, log = asyncio.run(
        proxied(tmp_path, loaded, unfinished=UNFINISHED, stop=False, guarded=True, engine=rules)
    )
    assert outcome.stopped is None
    assert b'"tools/call"' in log.read_bytes()


def test_the_framer_does_not_finish_a_line_unfinished_at_the_stop_without_a_guard(tmp_path):
    """Without the guard nothing but the framer holds the rest back: ``if stopped: continue``."""
    loaded = engaged(tmp_path)
    outcome, _, path, log = asyncio.run(
        proxied(tmp_path, loaded, unfinished=UNFINISHED, guarded=False, engine=Engine([OnClient()]))
    )
    assert outcome.stopped == "stop_file"
    assert b"initialize" in log.read_bytes()
    assert b"tools/call" not in log.read_bytes()
    received = [
        e
        for e in of_type(events_of(path), "message")
        if e["direction"] == "client_to_server" and e["incomplete"]
    ]
    assert [e["payload"]["data"] for e in received] == [UNFINISHED.decode()]


def test_the_framer_finishes_a_line_unfinished_at_the_end_of_the_input_without_a_stop(tmp_path):
    loaded = engaged(tmp_path)
    outcome, _, _, log = asyncio.run(
        proxied(
            tmp_path,
            loaded,
            unfinished=UNFINISHED,
            stop=False,
            guarded=False,
            engine=Engine([OnClient()]),
        )
    )
    assert outcome.stopped is None
    assert b'"tools/call"' in log.read_bytes()


class Sink:
    """Stands in for a stream writer, and keeps what it is given."""

    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.mark.parametrize("stopped", [False, True])
def test_settle_drops_the_held_line_unread_when_stopped_and_still_records_what_is_blocked(
    tmp_path, stopped
):
    recorded = []

    async def record(blocked):
        recorded.append(blocked)

    inner = Sink()
    writer = GuardedWriter(
        inner,
        ClientWriter(Sink()),
        ScopeGuard.of(engaged(tmp_path)),
        limit=1 << 20,
        record=record,
    )
    writer.write(call("shell", 1))  # not listed: blocked, and waiting to be recorded
    writer.write(UNFINISHED)  # allowed, and not ended
    assert inner.data == b"" and recorded == []
    asyncio.run(writer.settle(stopped=True) if stopped else writer.settle())
    assert len(recorded) == 1, "what was blocked is recorded either way"
    assert inner.data == (b"" if stopped else UNFINISHED)


def test_the_http_proxy_ends_in_order_when_the_stop_file_appears(tmp_path):
    loaded = engaged(tmp_path)
    sys.path.insert(0, str(FIXTURES))
    import http_server

    server = http_server.serve(0)
    url = f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"

    async def go():
        with Recorder.open(tmp_path / "events.jsonl", run_id="h", masker=Masker()) as recorder:
            proxy = HttpProxy(
                endpoint=url,
                recorder=recorder,
                limits=LIMITS,
                declaration=Declaration(**engagement.declaration_fields(loaded)),
                stop_check=lambda: engagement.stopped(loaded),
            )
            task = asyncio.create_task(proxy.run())
            await asyncio.sleep(0.3)
            Path(loaded.stop_file).write_text("{}")
            return await asyncio.wait_for(task, 20)

    try:
        outcome = asyncio.run(go())
    finally:
        server.shutdown()
        server.server_close()
    recorded = events_of(tmp_path / "events.jsonl")
    assert (outcome.reason, outcome.stopped) == ("stop_file", "stop_file")
    assert stops(recorded) == [("stop_file", "stop_file")]
    assert of_type(recorded, "run_finished")[0]["reason"] == "stop_file"


def test_the_http_proxy_passes_nothing_on_once_the_stop_file_is_there(tmp_path):
    loaded = engaged(tmp_path)
    answer = reference_answer("")
    # a connection closed with nothing sent (the stop) is answered with nothing
    target = Stub(lambda data: answer(data) if data else b"")
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    head = (
        f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(request)}\r\n\r\n"
    ).encode()

    async def go():
        with Recorder.open(tmp_path / "events.jsonl", run_id="h", masker=Masker()) as recorder:
            proxy = HttpProxy(
                endpoint=target.url,
                recorder=recorder,
                limits=LIMITS,
                declaration=Declaration(**engagement.declaration_fields(loaded)),
                stop_check=lambda: engagement.stopped(loaded),
            )
            task = asyncio.create_task(proxy.run())
            await proxy.launched.wait()
            assert await exchange_raw(proxy, head + request), "it is passed on while it may be"
            before = len(target.received)
            Path(loaded.stop_file).write_text("{}")
            # at once, before the proxy's own look at the file has ended the run
            with contextlib.suppress(ConnectionError, TimeoutError):
                assert not await exchange_raw(proxy, head + request)
            await asyncio.wait_for(task, 20)
            return before

    try:
        before = asyncio.run(go())
    finally:
        target.close()
    assert before == 1
    # a connection made and closed with nothing sent may leave an empty entry: not a request
    assert len([sent for sent in target.received if sent]) == 1, "a request got through"


class Written:
    """A writer that records what it is given."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def write(self, chunk: bytes) -> None:
        self.chunks.append(chunk)

    async def drain(self) -> None:
        pass

    def can_write_eof(self) -> bool:
        return False

    def close(self) -> None:
        pass


class Observed:
    """An observer that records what it is fed."""

    def __init__(self) -> None:
        self.fed: list[bytes] = []

    def request(self, chunk: bytes) -> None:
        self.fed.append(chunk)

    def response(self, chunk: bytes) -> None:
        self.fed.append(chunk)

    def reader_ended(self, side: str) -> None:
        pass

    def end(self, side: str) -> None:
        pass


def test_the_http_proxy_passes_nothing_on_after_the_stop_file_that_it_saw_is_removed(tmp_path):
    # The pump itself, not a run: in a run the watcher shuts the connections down at once, and a
    # request that never arrives would say nothing about what the pump does with it.
    async def go():
        with Recorder.open(tmp_path / "events.jsonl", run_id="h", masker=Masker()) as recorder:
            proxy = HttpProxy(
                endpoint="http://127.0.0.1:9/mcp",
                recorder=recorder,
                limits=LIMITS,
                stop_check=lambda: False,  # the file is gone now
            )
        proxy._stop_file_seen = True  # it was there once
        reader = asyncio.StreamReader()
        reader.feed_data(b"POST /mcp HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
        reader.feed_eof()
        writer, observer = Written(), Observed()
        await proxy._pump(reader, writer, observer, "request")
        return writer.chunks, observer.fed

    assert asyncio.run(go()) == ([], []), "a request got through"


def stop_checked(tmp_path: Path, answers: list[bool]) -> tuple[Proxy, list[int]]:
    """A proxy that is never run, whose stop check gives ``answers`` in turn, and the count."""
    asked: list[int] = []

    def check() -> bool:
        asked.append(1)
        return answers[len(asked) - 1]

    with Recorder.open(tmp_path / "u.jsonl", run_id="u", masker=Masker()) as recorder:
        proxy = Proxy(
            argv=["x"],
            recorder=recorder,
            limits=LIMITS,
            client_in=None,
            client_out=None,
            stop_check=check,
        )
    return proxy, asked


def test_a_stop_file_that_was_seen_stops_the_run_without_asking_again(tmp_path):
    async def go():
        proxy, asked = stop_checked(tmp_path, [True, False])
        assert proxy._stop_file_stops() is True
        assert proxy._stop_file_stops() is True
        return len(asked)

    assert asyncio.run(go()) == 1


@pytest.mark.parametrize(
    "stop",
    [
        lambda proxy: proxy.stop_run("window_closed"),
        lambda proxy: proxy._on_signal(signal.SIGTERM),
    ],
    ids=["window", "signal"],
)
def test_a_stop_for_another_reason_does_not_make_the_stop_file_stop_the_run(tmp_path, stop):
    async def go():
        proxy, asked = stop_checked(tmp_path, [False, False])
        stop(proxy)
        assert proxy._stop_file_stops() is False
        assert proxy._stop_file_stops() is False
        return len(asked)

    assert asyncio.run(go()) == 2


# -- the fleet -------------------------------------------------------------------------------


def test_a_fleet_whose_stop_file_is_there_is_refused_before_anything_starts(tmp_path):
    path = engagement_file(tmp_path)
    loaded = engagement.load(path)
    stop_command(path)
    launch = launcher_under(loaded.digest)
    with Store.open(tmp_path / "s.sqlite") as store, pytest.raises(fleet.FleetError) as refusal:
        fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launch,
                  engagement=loaded, now=NOW)  # fmt: skip
    assert refusal.value.condition == "stop_file"
    assert launch.handed == []


def test_a_fleet_starts_no_further_run_once_the_stop_file_appears(tmp_path):
    path = engagement_file(tmp_path)
    loaded = engagement.load(path)
    inner = launcher_under(loaded.digest)

    def launch(job, *args, **kwargs):
        # the first run is going when the operator stops the engagement
        stop_command(path, "--reason", "stop now")
        time.sleep(1.0)  # longer than the fleet's look
        return inner(job, *args, **kwargs)

    with Store.open(tmp_path / "s.sqlite") as store:
        record = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launch,
                           engagement=loaded, now=NOW, parallel=1)  # fmt: skip
    assert len(inner.handed) == 1, "the second run was never launched"
    assert record.interrupted == "stop_file"
    by_entry = {result.entry: (result.state, result.causes) for result in record.results.values()}
    assert by_entry == {
        "reference-server": ("complete", ()),
        "poison-server": ("unfiled", ("interrupted",)),
    }
    assert "interrupted by stop_file: 0 run(s) stopped and 1 never started" in record.problems[0]


def test_a_fleet_stops_the_run_that_is_going_when_the_stop_file_appears(tmp_path):
    path = engagement_file(tmp_path)
    loaded = engagement.load(path)
    ended = []

    def launch(job, pins, manifest_path, out_dir, *, step_timeout, job_timeout,
               client_settle_timeout, processes, engagement_path=None):  # fmt: skip
        # a run that would go on for ten minutes; the operator stops the engagement meanwhile
        process = processes.start([sys.executable, "-c", "import time; time.sleep(600)"])
        if process is None:  # the fleet is stopping: no run starts
            return fleet.Launched(None, None, interrupted=fleet.NOT_STARTED)
        stop_command(path, "--reason", "stop now")
        process.communicate()
        ended.append(process.returncode)
        stopped = processes.ended(process)
        return fleet.Launched(
            process.returncode, None, interrupted=fleet.STOPPED if stopped else None
        )

    with Store.open(tmp_path / "s.sqlite") as store:
        started = time.monotonic()
        record = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launch,
                           engagement=loaded, now=NOW, parallel=1)  # fmt: skip
    assert time.monotonic() - started < 60, "the run was not left to its ten minutes"
    assert ended == [-signal.SIGTERM], "asked to stop, and it stopped"
    assert record.interrupted == "stop_file"
    assert {result.causes for result in record.results.values()} == {("interrupted",)}
    assert "interrupted by stop_file: 1 run(s) stopped and 1 never started" in record.problems[0]


# -- a signal --------------------------------------------------------------------------------


@pytest.mark.parametrize("number", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_ends_drive_in_order_and_leaves_no_process(tmp_path, number):
    launcher = tmp_path / "launcher.py"
    launcher.write_text(LAUNCHER)
    out = tmp_path / "runs"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "drive", "--out-dir", str(out), "-q",
         "--step-timeout", "20", "--",
         sys.executable, str(launcher), str(tmp_path / "log"), "-", str(tmp_path / "pids"),
         "--silent-after-handshake"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )  # fmt: skip
    try:
        log = tmp_path / "log"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if log.exists() and b'"tools/list"' in log.read_bytes():
                break
            time.sleep(0.05)
        else:
            pytest.fail("the run never got to its first listing")
        process.send_signal(number)
        process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    (path,) = out.glob("*/events.jsonl")
    recorded = events_of(path)
    assert stops(recorded) == [(number.name, "signal")]
    (finished,) = of_type(recorded, "run_finished")
    assert finished["reason"] == "signal"
    assert of_type(recorded, "server_exited") != []
    assert of_type(recorded, "script_finished") != [], "the driver wrote how its script ended"
    pids = [int(pid) for pid in (tmp_path / "pids").read_text().split()]
    assert all(gone(pid) for pid in pids)
    assert process.returncode == 3
    assert verdict.read(path).state == verdict.INCOMPLETE


# -- a stop that is not one of the three ------------------------------------------------------


class ThrowsOnCall:
    """A scenario rule with a bug, which stops the run (the default policy) as the first call's
    answer passes."""

    name = "throws-on-call"
    directions = frozenset({events.Direction.SERVER_TO_CLIENT})

    def act(self, direction, document, responded_method):
        if responded_method == "tools/call":
            raise ValueError("a rule with a bug")


def other_stop(tmp_path: Path, **how) -> Driven:
    return drive(tmp_path, engaged(tmp_path), script=two_calls(), **how)


def assert_left_to_the_channel(seen: Driven, reason: str) -> None:
    """What a stop that is not one of the three leaves in the recording: no ``run_stopped``, no
    step marked as halted, and a verdict that follows what was sent and answered, as it did
    before a run could be halted — not a halt the verdict has no cause for."""
    recorded = seen.recorded
    assert of_type(recorded, "run_stopped") == []
    assert seen.outcome.halted is None
    skipped = of_type(recorded, "step_skipped")
    assert "run_halted" not in [e["reason"] for e in skipped]
    (finished,) = of_type(recorded, "run_finished")
    assert finished["reason"] == reason
    (script_ended,) = of_type(recorded, "script_finished")
    cut = bool(skipped) or bool(of_type(recorded, "step_unanswered"))
    assert (script_ended["inventory"] == "partial") == cut
    judged = verdict.read(seen.path)
    if cut:
        assert judged.state == verdict.INCOMPLETE
    else:
        assert judged.state == verdict.COMPLETE and tool_calls_seen(seen.log) == 2


def test_a_duration_limit_between_two_steps_leaves_the_driver_to_the_channel(tmp_path):
    seen = other_stop(tmp_path, after_call=lambda proxy: proxy._request_stop("duration_limit"))
    assert_left_to_the_channel(seen, "duration_limit")


def test_the_stop_of_a_scenario_rule_between_two_steps_leaves_the_driver_to_the_channel(tmp_path):
    seen = other_stop(tmp_path, engine=Engine([ThrowsOnCall()]))
    assert_left_to_the_channel(seen, "rule_error")


def halting(reason: str) -> Driver:
    async def nothing(**fields) -> None:
        return None

    return Driver(two_calls(), ClientChannel(), record_skipped=nothing, halt=lambda: reason)


def test_the_driver_halts_only_for_the_three_words():
    for reason in ("duration_limit", "rule_error", "client_eof", "engine_error", ""):
        driver = halting(reason)
        assert driver._halt_reason() is None
    for reason in events.STOPPED_BECAUSE:
        driver = halting(reason)
        assert driver._halt_reason() == reason


def stopped_recording(tmp_path: Path, because: str) -> Driven:
    """A real driven run, stopped between its steps for the reason ``because``, with the steps
    it did not send recorded as skipped."""
    loaded = engaged(tmp_path)
    if because == "signal":
        return drive(
            tmp_path,
            loaded,
            script=two_calls(),
            after_call=lambda proxy: proxy._on_signal(signal.SIGTERM),
        )
    if because == "stop_file":
        return drive(tmp_path, loaded, script=two_calls(), trigger=Path(loaded.stop_file))
    flag = tmp_path / "window-closed"
    return drive(tmp_path, loaded, script=two_calls(), trigger=flag, clock=Clock(loaded, flag))


@pytest.mark.parametrize("because", events.STOPPED_BECAUSE)
def test_a_recording_with_skipped_steps_of_each_stop_is_judged_interrupted(tmp_path, because):
    seen = stopped_recording(tmp_path, because)
    skipped = of_type(seen.recorded, "step_skipped")
    assert skipped and {e["reason"] for e in skipped} == {"run_halted"}
    assert [e["because"] for e in of_type(seen.recorded, "run_stopped")] == [because]
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes
    assert (judged.exit_code, list(judged.causes)) == (3, ["interrupted"])


# -- the verdict -----------------------------------------------------------------------------


def run_events(stopped: dict) -> list[dict]:
    return [
        {"type": "run_started", "mode": "driver", "isolation": "host", "script": "x"},
        {"type": "script_finished", "inventory": "partial"},
        stopped,
        {
            "type": "run_finished",
            "findings_by_statement": {},
            "server_output_bytes": 100,
            "client_input_bytes": 100,
            "server_exited_first": False,
        },
    ]


@pytest.mark.parametrize("because", ["stop_file", "window_closed"])
def test_a_run_stopped_by_the_file_or_the_window_is_judged_as_one_stopped_by_a_signal(because):
    by_signal = verdict.assess(run_events({"type": "run_stopped", "signal": "SIGTERM"}))
    judged = verdict.assess(
        run_events({"type": "run_stopped", "signal": because, "because": because})
    )
    assert (judged.state, judged.exit_code, judged.causes) == (
        by_signal.state,
        by_signal.exit_code,
        by_signal.causes,
    )
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes


def test_the_stop_is_recorded_with_the_word_that_says_why():
    with pytest.raises(ValueError):
        Recorder.run_stopped(None, 1, 1, signal="x", because="whim")  # type: ignore[arg-type]
    assert events.STOPPED_BECAUSE == ("signal", "stop_file", "window_closed")


# -- the module frame ------------------------------------------------------------------------


def test_echo_runs_through_the_frame_and_everything_it_did_is_recorded(tmp_path):
    loaded = engaged(tmp_path)
    secret = "Bearer " + "Zy9Xw8Vu7Ts6" * 3
    seen = drive(
        tmp_path,
        loaded,
        probe=PROBES["echo"],
        options={"tool": "read", "text": secret},
    )
    recorded = seen.recorded
    assert seen.outcome.called == ("read",) and seen.outcome.halted is None
    (called,) = of_type(recorded, "step_called")
    assert (called["step"], called["tool"]) == ("tools/call", "read")
    assert tool_calls_seen(seen.log) == 1
    assert secret not in seen.path.read_text()
    assert verdict.read(seen.path).state == verdict.COMPLETE


def test_the_module_and_its_options_are_in_run_started_masked(tmp_path):
    secret = "Bearer " + "Zy9Xw8Vu7Ts6" * 3
    loaded = engaged(tmp_path)
    (tmp_path / "runs").mkdir()
    code = cli_drive(
        tmp_path,
        loaded,
        "--probe",
        "echo",
        "--probe-option",
        "tool=read",
        "--probe-option",
        f"text={secret}",  # fmt: skip
    )
    assert code == 0
    (path,) = (tmp_path / "runs").glob("*/events.jsonl")
    started = events_of(path)[0]
    assert started["probe"]["name"] == "echo" and started["script"] == "probe:echo"
    assert started["probe"]["options"]["tool"] == "read"
    assert secret not in path.read_text() and secret not in started["probe"]["options"]["text"]
    called = of_type(events_of(path), "step_called")
    assert [e["tool"] for e in called] == ["read"]


def named_run(tmp_path: Path, name: str, how: str, listed: bool, call_result: str) -> Driven:
    """A run that calls the tool ``name``, which the server lists, by ``--probe echo`` or by a
    script; the engagement file lists it too, or there is no file and so no list."""
    loaded = engaged(tmp_path, tools=[{"name": name, "writes": False}]) if listed else None
    script = None
    if how == "script":
        script = Script(
            name="named",
            protocol_version="2025-06-18",
            client_info={"name": "t", "version": "0"},
            capabilities={},
            steps=(
                Step("tools/list", requires="tools", paginate=True),
                CallStep(tool=name, arguments={"text": "hi"}),
            ),
        )
    return drive(
        tmp_path,
        loaded,
        script=script,
        probe=PROBES["echo"] if how == "probe" else None,
        options={"tool": name} if how == "probe" else None,
        tools=("--tool-name", name),
        call_result=call_result,
    )


def tool_fields(recorded: list[dict]) -> dict[str, list[str]]:
    """The four places a run writes the name of a tool it called."""
    (finished,) = of_type(recorded, "script_finished")
    return {
        "step_called.tool": [e["tool"] for e in of_type(recorded, "step_called")],
        "call_failed.tool": [e["tool"] for e in of_type(recorded, "call_failed")],
        "script_finished.called": list(finished["called"]),
        "script_finished.failed": list(finished["failed"]),
    }


@pytest.mark.parametrize("listed", [True, False])
@pytest.mark.parametrize("call_result", ["text", "rpc-error", "tool-error"])
@pytest.mark.parametrize("how", ["probe", "script"])
def test_a_token_in_the_name_of_a_called_tool_is_in_none_of_the_events(
    tmp_path, how, call_result, listed
):
    secret = token()
    # Only --probe-option tool=... can bring a name past the cut at 128 (a script file refuses
    # one): there the token starts at 110, so a cut first would leave 18 characters of it. A
    # script's name is within the cut, the token whole in it.
    name = "a" * 109 + "/" + secret if how == "probe" else "a" * 50 + "/" + secret
    assert len(name) <= (1000 if how == "probe" else script_file.MAX_TOOL_LENGTH)
    seen = named_run(tmp_path, name, how, listed, call_result)
    assert seen.outcome.called == (name,)
    fields = tool_fields(seen.recorded)
    failing = call_result != "text"
    assert len(fields["step_called.tool"]) == 1 and len(fields["script_finished.called"]) == 1
    assert bool(fields["call_failed.tool"]) == failing == bool(fields["script_finished.failed"])
    assert not leaks(secret, seen.path.read_text())
    for field, shown in fields.items():
        for text in shown:
            assert len(text) <= events.MAX_METHOD_LENGTH, field
            assert not any(part in text for part in parts_of(secret, size=4)), field


@pytest.mark.parametrize("call_result", ["text", "tool-error"])
def test_an_ordinary_name_of_a_called_tool_stays_as_it_is_in_all_four_events(tmp_path, call_result):
    seen = named_run(tmp_path, "read", "probe", True, call_result)
    fields = tool_fields(seen.recorded)
    failing = call_result != "text"
    assert fields["step_called.tool"] == ["read"]
    assert fields["script_finished.called"] == ["read"]
    assert fields["call_failed.tool"] == (["read"] if failing else [])
    assert fields["script_finished.failed"] == (["read"] if failing else [])


def test_a_script_run_records_no_probe(tmp_path):
    seen = drive(tmp_path, None, script=two_calls())
    assert seen.recorded[0]["probe"] is None


def test_a_tool_outside_tools_is_stopped_by_the_guard_and_never_sent(tmp_path):
    loaded = engaged(tmp_path)
    seen = drive(tmp_path, loaded, probe=PROBES["echo"], options={"tool": OUTSIDE})
    assert tool_calls_seen(seen.log) == 0
    (blocked,) = of_type(seen.recorded, "call_blocked")
    assert (blocked["cause"], blocked["where"], blocked["tool"]) == (
        "tool_not_listed",
        "driver",
        OUTSIDE,
    )
    assert seen.outcome.blocked == ("tool_not_listed", OUTSIDE)
    assert of_type(seen.recorded, "step_called") == []
    assert verdict.read(seen.path).state == verdict.INCOMPLETE


def test_a_tool_the_server_did_not_list_ends_the_module_with_a_cause_and_no_call(tmp_path):
    loaded = engaged(tmp_path, tools=[{"name": "ghost", "writes": False}])
    seen = drive(tmp_path, loaded, probe=PROBES["echo"], options={"tool": "ghost"})
    assert tool_calls_seen(seen.log) == 0
    (skipped,) = of_type(seen.recorded, "step_skipped")
    assert (skipped["step"], skipped["reason"]) == ("tools/call", "tool_not_listed")
    assert of_type(seen.recorded, "step_called") == []
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "step_not_sent" in judged.causes


def test_through_the_command_line_echo_with_a_stop_file_is_refused(tmp_path, nothing_starts):
    loaded = engaged(tmp_path)
    stop_command(Path(loaded.source))
    assert cli_drive(tmp_path, loaded, *RUNS["probe"]) == 2
    assert refusals(tmp_path) == ["stop_file"]


class Greedy(Probe):
    name = "greedy"
    description = "asks for more than it may"
    max_calls = 2

    async def run(self, context: Context, options: Mapping[str, str]) -> None:
        await context.tools()
        await context.call("read", {"text": "one"})
        await context.call("read", {"text": "two"})  # the third request


def test_max_calls_is_enforced_and_the_request_over_the_limit_is_not_sent(tmp_path):
    loaded = engaged(tmp_path)
    seen = drive(tmp_path, loaded, probe=Greedy())
    assert tool_calls_seen(seen.log) == 1
    assert [e["tool"] for e in of_type(seen.recorded, "step_called")] == ["read"]
    (skipped,) = of_type(seen.recorded, "step_skipped")
    assert (skipped["step"], skipped["reason"]) == ("tools/call", "probe_calls_exhausted")
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "step_not_sent" in judged.causes


class Counting(Probe):
    name = "counting"
    description = "makes as many calls as its limit"
    max_calls = 3
    paced = 0

    async def run(self, context: Context, options: Mapping[str, str]) -> None:
        await context.tools()
        await context.call("read", {})
        await context.call("read", {})


def test_a_module_within_its_limit_is_not_ended(tmp_path):
    loaded = engaged(tmp_path)
    seen = drive(tmp_path, loaded, probe=Counting())
    assert tool_calls_seen(seen.log) == 2
    assert of_type(seen.recorded, "step_skipped") == []
    assert verdict.read(seen.path).state == verdict.COMPLETE


class Broken(Probe):
    name = "broken"
    description = "raises"
    max_calls = 1

    async def run(self, context: Context, options: Mapping[str, str]) -> None:
        raise RuntimeError("the module has a bug")


def test_a_module_that_raises_is_recorded_as_a_mistake_of_the_tool_and_the_recording_stands(
    tmp_path,
):
    seen = drive(tmp_path, engaged(tmp_path), probe=Broken())
    (skipped,) = of_type(seen.recorded, "step_skipped")
    assert (skipped["step"], skipped["reason"]) == ("probe", "driver_error")
    assert of_type(seen.recorded, "script_finished") != []
    assert verdict.read(seen.path).state == verdict.INCOMPLETE


def test_the_frame_has_a_pacing_hook_that_every_request_passes_and_that_does_nothing(
    tmp_path, monkeypatch
):
    from mcp_kymograph import driver as driver_module

    paced = []
    real = driver_module._ProbeContext.pace

    async def counted(self):
        paced.append(1)
        await real(self)

    monkeypatch.setattr(driver_module._ProbeContext, "pace", counted)
    seen = drive(tmp_path, engaged(tmp_path), probe=PROBES["echo"], options={"tool": "read"})
    assert len(paced) == 2  # the listing and the call
    assert tool_calls_seen(seen.log) == 1


def test_the_module_limits_the_script_limits_do_not_apply_to():
    assert MAX_CALLS == 64
    with pytest.raises(TypeError):

        class TooMany(Probe):
            name = "too-many"
            description = "x"
            max_calls = MAX_CALLS + 1

            async def run(self, context, options):
                pass

    with pytest.raises(TypeError):

        class Nameless(Probe):
            name = "Not A Name"
            description = "x"
            max_calls = 1

            async def run(self, context, options):
                pass

    assert all(1 <= probe.max_calls <= MAX_CALLS for probe in PROBES.values())


def test_the_echo_options_are_checked_by_the_module():
    echo = PROBES["echo"]
    echo.check({"tool": "read"})
    echo.check({"tool": "read", "text": "x"})
    with pytest.raises(ProbeError):
        echo.check({})
    with pytest.raises(ProbeError):
        echo.check({"tool": "read", "more": "x"})


def test_a_module_ended_by_the_frame_is_told_why():
    assert ProbeEnded("run_halted").reason == "run_halted"


# -- every page of a listing is held against the end of the run and max_calls ------------------

#: A server whose ``tools/list`` always has a next page (a listing would end at MAX_PAGES).
ENDLESS = ("--tool-name", "read", "--pages", "1000")


def lists_seen(log: Path) -> int:
    return log.read_bytes().count(b'"tools/list"') if log.exists() else 0


class ClosesAfterPages:
    """A wall clock whose window closes once the server has been sent ``pages`` listings."""

    def __init__(self, loaded: engagement.Engagement, log: Path, pages: int) -> None:
        self._until = loaded.window_until
        self._log = log
        self._pages = pages

    def __call__(self) -> datetime:
        if lists_seen(self._log) >= self._pages:
            return self._until + timedelta(minutes=1)
        return self._until - timedelta(hours=1)


def halted_listing(seen: Driven) -> dict:
    """The one listing step that was not sent, and for the word of the halt."""
    (skipped,) = [
        e
        for e in of_type(seen.recorded, "step_skipped")
        if e["step"] == "tools/list" and e["detail"]
    ]
    assert skipped["reason"] == "run_halted"
    return skipped


@pytest.mark.parametrize("how", ["probe", "script"])
def test_a_window_that_closes_during_a_listing_stops_it_before_the_next_page(tmp_path, how):
    loaded = engaged(tmp_path)
    seen = drive(
        tmp_path,
        loaded,
        probe=PROBES["echo"] if how == "probe" else None,
        script=two_calls() if how == "script" else None,
        options={"tool": "read"},
        clock=ClosesAfterPages(loaded, tmp_path / "server.log", 3),
        tools=ENDLESS,
    )
    assert lists_seen(seen.log) == 3
    assert tool_calls_seen(seen.log) == 0
    assert halted_listing(seen)["detail"] == "3"
    assert stops(seen.recorded) == [("window_closed", "window_closed")]
    (finished,) = of_type(seen.recorded, "run_finished")
    assert (finished["reason"], finished["window_exceeded"]) == ("window_closed", True)
    (done,) = of_type(seen.recorded, "script_finished")
    assert done["inventory"] == "partial"
    assert all(gone(pid) for pid in seen.server_pids())
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "interrupted" in judged.causes


@pytest.mark.parametrize("how", ["probe", "script"])
def test_a_stop_file_that_appears_between_two_pages_stops_the_listing(tmp_path, how, monkeypatch):
    loaded = engaged(tmp_path)
    log = tmp_path / "server.log"
    real = engagement.stopped

    def stopped_after_three(found):
        if lists_seen(log) >= 3:
            Path(found.stop_file).write_text("{}")
        return real(found)

    monkeypatch.setattr(engagement, "stopped", stopped_after_three)
    seen = drive(
        tmp_path,
        loaded,
        probe=PROBES["echo"] if how == "probe" else None,
        script=two_calls() if how == "script" else None,
        options={"tool": "read"},
        tools=ENDLESS,
    )
    assert lists_seen(seen.log) == 3
    assert tool_calls_seen(seen.log) == 0
    assert halted_listing(seen)["detail"] == "3"
    assert stops(seen.recorded) == [("stop_file", "stop_file")]
    (finished,) = of_type(seen.recorded, "run_finished")
    assert finished["reason"] == "stop_file"


class JustListing(Probe):
    name = "just-listing"
    description = "lists the tools"
    max_calls = 3

    async def run(self, context: Context, options: Mapping[str, str]) -> None:
        await context.tools()


def test_every_page_of_a_listing_counts_against_max_calls(tmp_path):
    seen = drive(tmp_path, engaged(tmp_path), probe=JustListing(), tools=ENDLESS)
    assert lists_seen(seen.log) == 3
    (skipped,) = of_type(seen.recorded, "step_skipped")
    assert (skipped["step"], skipped["reason"]) == ("tools/list", "probe_calls_exhausted")
    judged = verdict.read(seen.path)
    assert judged.state == verdict.INCOMPLETE and "step_not_sent" in judged.causes


def test_a_listing_of_two_pages_and_echo_run_as_they_did(tmp_path):
    seen = drive(
        tmp_path,
        engaged(tmp_path),
        probe=PROBES["echo"],
        options={"tool": "read"},
        tools=("--tool-name", "read", "--pages", "2"),
    )
    assert (lists_seen(seen.log), tool_calls_seen(seen.log)) == (2, 1)
    assert of_type(seen.recorded, "step_skipped") == []
    assert verdict.read(seen.path).state == verdict.COMPLETE


def test_echo_may_make_a_whole_listing_and_its_call():
    assert PROBES["echo"].max_calls == MAX_PAGES + 1


class Pages:
    """The answers a driver's ``_request`` gives in turn: a page with a next page, or None (the
    response stream broke). Every request is noted."""

    def __init__(self, *answers: dict | None) -> None:
        self._answers = list(answers)
        self.asked: list[dict | None] = []

    async def __call__(self, method, params, **_):
        self.asked.append(params)
        return self._answers.pop(0)


def page(number: int) -> dict:
    return {"jsonrpc": "2.0", "id": number, "result": {"tools": [], "nextCursor": f"page-{number}"}}


def broken_listing(probe: Probe, *, closes_at: int | None = None):
    """The context of ``probe`` on a modern-era driver whose second request breaks its stream (the
    third is the request made again, the fourth would be the next page); with ``closes_at`` the
    window closes once that many requests were asked. Also the pages and what was recorded."""
    skipped: list[dict] = []
    reissued: list[dict] = []
    pages = Pages(page(1), None, page(2), page(3))

    async def record_skipped(**fields) -> None:
        skipped.append(fields)

    async def record_reissued(**fields) -> None:
        reissued.append(fields)

    def halt() -> str | None:
        return "window_closed" if closes_at and len(pages.asked) >= closes_at else None

    driver = Driver(
        two_calls(),
        ClientChannel(),
        record_skipped=record_skipped,
        record_reissued=record_reissued,
        halt=halt,
    )
    driver._era = eras.ERA_MODERN
    driver._failure = "stream_broken"
    driver._request = pages
    return _ProbeContext(driver, probe, {"tools": {}}), pages, skipped, reissued


def test_a_request_made_again_is_held_against_the_window_before_it_is_sent():
    context, pages, skipped, reissued = broken_listing(PROBES["echo"], closes_at=2)
    asyncio.run(context.tools())  # the answers came: the listing ends, the next check halts
    assert len(pages.asked) == 2, "the request made again was sent"
    assert reissued == []
    assert [(s["step"], s["reason"], s["detail"]) for s in skipped] == [
        ("tools/list", "run_halted", "1")
    ]


def test_a_request_made_again_counts_against_max_calls():
    class Two(JustListing):
        name = "two"
        max_calls = 2

    context, pages, skipped, reissued = broken_listing(Two())
    with pytest.raises(ProbeEnded) as ended:
        asyncio.run(context.tools())
    assert ended.value.reason == "probe_calls_exhausted"
    assert len(pages.asked) == 2, "the request made again was sent"
    assert reissued == []
    assert [(s["step"], s["reason"]) for s in skipped] == [("tools/list", "probe_calls_exhausted")]


def test_a_request_made_again_within_the_limit_is_sent():
    context, pages, skipped, reissued = broken_listing(JustListing())
    with pytest.raises(ProbeEnded):  # the fourth request is over the limit of three
        asyncio.run(context.tools())
    assert len(pages.asked) == 3
    assert [r["page"] for r in reissued] == [1]
    assert [s["reason"] for s in skipped] == ["probe_calls_exhausted"]
