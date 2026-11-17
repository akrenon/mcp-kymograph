"""Input errors are refused when they are read, before anything starts.

A bound that cannot hold — zero, a negative number, nan, inf — and an output directory that
cannot be created or written into are the operator's input being wrong. They are refused with
the exit code for input errors (2) and a line that says which input and why: never a
traceback, and never a run that ends in some state (server_failed, a stopped recording) whose
cause was the input.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, fleet
from mcp_kymograph.fleet import FleetError, Pins
from mcp_kymograph.store import Store

TOY = str(Path(__file__).parent / "fixtures" / "toy_server.py")
PROJECT = Path(__file__).parent / "fixtures" / "corpus" / "manifest.yaml"

#: Every bound read from the command line, by the commands that take it, and whether it counts
#: (a whole number) or is in seconds.
COUNTS = ["--max-message-bytes", "--queue-size"]
SECONDS = ["--max-duration"]
DRIVE_SECONDS = ["--step-timeout", "--client-settle-timeout"]
FLEET_SECONDS = ["--step-timeout", "--job-timeout", "--client-settle-timeout"]

BAD_COUNTS = ["0", "-1", "-4096", "1.5", "nan"]
BAD_SECONDS = ["0", "-1", "-0.5", "nan", "inf", "-inf", "NaN", "Infinity", "1e400"]


def cases() -> list[tuple[str, str, str]]:
    found = []
    for command in ("run", "drive"):
        found += [(command, flag, value) for flag in COUNTS for value in BAD_COUNTS]
        found += [(command, flag, value) for flag in SECONDS for value in BAD_SECONDS]
    found += [("drive", flag, value) for flag in DRIVE_SECONDS for value in BAD_SECONDS]
    found += [("fleet", flag, value) for flag in FLEET_SECONDS for value in BAD_SECONDS]
    return found


def argv(command: str, tmp_path: Path, *extra: str) -> list[str]:
    if command == "fleet":
        store = str(tmp_path / "store.sqlite")
        return ["fleet", "run", "--manifest", str(PROJECT), "--store", store,
                "--out-dir", str(tmp_path / "runs"), *extra]  # fmt: skip
    return [command, "--out-dir", str(tmp_path / "runs"), *extra, "--", sys.executable, TOY]


@pytest.mark.parametrize(("command", "flag", "value"), cases())
def test_a_bound_that_cannot_hold_is_refused_when_read_and_nothing_starts(
    tmp_path, monkeypatch, capsys, command, flag, value
):
    def must_not_start(*_args, **_kwargs):
        raise AssertionError("nothing may start on an input error")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_start)
    monkeypatch.setattr(fleet, "run", must_not_start)
    monkeypatch.setattr(fleet, "pin", must_not_start)
    with pytest.raises(SystemExit) as refused:
        cli.main(argv(command, tmp_path, f"{flag}={value}"))
    assert refused.value.code == cli.EXIT_REFUSED
    said = capsys.readouterr().err
    assert f"argument {flag}" in said and value in said, said
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "store.sqlite").exists()


@pytest.mark.parametrize(
    ("flag", "value", "expected"),
    [
        ("--max-message-bytes", "1", 1),
        ("--queue-size", "7", 7),
        ("--max-duration", "0.25", 0.25),
        ("--max-duration", "1e-3", 0.001),
    ],
)
def test_a_bound_that_can_hold_is_taken_as_given(flag, value, expected):
    """The other direction: the check refuses what cannot hold, nothing more."""
    args = cli.build_parser().parse_args(["run", flag, value])
    assert getattr(args, flag.lstrip("-").replace("-", "_")) == expected


def run_cli(tmp_path: Path, command: str, out_dir: Path) -> subprocess.CompletedProcess:
    """A whole process, as a caller sees it, against a server that leaves a mark if started."""
    marker = tmp_path / "server-started"
    server = f"open({str(marker)!r}, 'w').write('started')"
    extra = ["--step-timeout", "5"] if command == "drive" else []
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", command, "-q", "--out-dir", str(out_dir),
         *extra, "--", sys.executable, "-c", server],
        input=b"", capture_output=True, timeout=60, check=False,
    )  # fmt: skip


def unusable_out_dir(tmp_path: Path, kind: str) -> Path:
    """An output directory that cannot be used, of one kind."""
    if kind == "file":
        out_dir = tmp_path / "a-file"
        out_dir.write_text("not a directory\n")
        return out_dir
    if kind == "symlink-loop":
        (tmp_path / "loop").symlink_to("loop")
        return tmp_path / "loop"
    return tmp_path / ("x" * 300)  # longer than any file name may be


@pytest.mark.parametrize("kind", ["file", "symlink-loop", "name-too-long"])
@pytest.mark.parametrize("command", ["run", "drive"])
def test_an_output_directory_that_cannot_be_used_is_refused_before_the_server_starts(
    tmp_path, command, kind
):
    out_dir = unusable_out_dir(tmp_path, kind)
    done = run_cli(tmp_path, command, out_dir)
    assert done.returncode == cli.EXIT_REFUSED, done.stderr.decode()
    assert b"Traceback" not in done.stderr
    assert b"output directory cannot be created or written into" in done.stderr
    assert not (tmp_path / "server-started").exists(), "the server must not have been started"
    if kind == "file":
        assert out_dir.read_text() == "not a directory\n"


@pytest.mark.skipif(os.geteuid() == 0, reason="root may write into a directory it cannot")
@pytest.mark.parametrize("command", ["run", "drive"])
def test_an_output_directory_that_cannot_be_created_is_refused_before_the_server_starts(
    tmp_path, command
):
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    try:
        done = run_cli(tmp_path, command, locked / "runs")
    finally:
        locked.chmod(0o700)
    assert done.returncode == cli.EXIT_REFUSED, done.stderr.decode()
    assert b"Traceback" not in done.stderr
    assert b"output directory cannot be created or written into" in done.stderr
    assert not (tmp_path / "server-started").exists(), "the server must not have been started"
    assert not (locked / "runs").exists()


@pytest.mark.parametrize("kind", ["file", "symlink-loop", "name-too-long"])
def test_a_fleet_whose_output_directory_cannot_be_used_starts_no_run_and_files_nothing(
    tmp_path, kind
):
    out_dir = unusable_out_dir(tmp_path, kind)
    pins = Pins("runc", "sha256:" + "5a" * 32, "sha256:" + "7a" * 32)

    def must_not_launch(*_args, **_kwargs):
        raise AssertionError("no run may be started")

    with Store.open(tmp_path / "s.sqlite") as store:
        with pytest.raises(FleetError, match="cannot be created or written into"):
            fleet.run(PROJECT, store, out_dir, pins=pins, launcher=must_not_launch)
        assert store.fleets() == []


def test_a_fleet_whose_output_directory_is_a_file_exits_2_on_the_command_line(
    tmp_path, monkeypatch, capsys
):
    out_dir = tmp_path / "a-file"
    out_dir.write_text("")
    monkeypatch.setattr(fleet, "pin", lambda *_: Pins("runc", "a", "b"))
    code = cli.main(["fleet", "run", "--manifest", str(PROJECT), "--store",
                     str(tmp_path / "s.sqlite"), "--out-dir", str(out_dir), "-q"])  # fmt: skip
    assert code == cli.EXIT_REFUSED
    said = capsys.readouterr()
    assert "cannot be created or written into" in said.err
    assert json.loads(said.out or "null") is None, "no fleet output for a fleet that never ran"


# -- a fleet's destination, checked once ----------------------------------------------------


def git_tree(path: Path, ignored: str | None = None) -> Path:
    import shutil

    path.mkdir(parents=True)
    git = shutil.which("git")
    assert git, "these tests need a git binary"
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=path, check=True)  # noqa: S603
    if ignored is not None:
        (path / ".gitignore").write_text(f"/{ignored}/\n")
    return path


def test_a_fleet_whose_destination_git_could_commit_is_refused_once_before_any_run(tmp_path):
    """Each run checks its own destination and would refuse — one result after another, all
    of them `refused`. The fleet refuses once, before the first run exists."""
    repo = git_tree(tmp_path / "repo")
    pins = Pins("runc", "sha256:" + "5a" * 32, "sha256:" + "7a" * 32)

    def must_not_launch(*_args, **_kwargs):
        raise AssertionError("no run may be started")

    with Store.open(tmp_path / "s.sqlite") as store:
        with pytest.raises(FleetError, match="git working tree") as refused:
            fleet.run(PROJECT, store, repo / "runs", pins=pins, launcher=must_not_launch)
        assert store.fleets() == []
    assert "Nothing was started." in str(refused.value)
    assert not (repo / "runs").exists()


def test_a_fleet_whose_destination_git_ignores_runs(tmp_path):
    """The other direction: the same tree with the directory ignored is a place to write."""
    from test_fleet import launcher, pair

    repo = git_tree(tmp_path / "repo", ignored="runs")
    pins = Pins("runc", "sha256:" + "5a" * 32, "sha256:" + "7a" * 32)
    plan = launcher({"reference-server": {}, "poison-server": {}})
    with Store.open(tmp_path / "s.sqlite") as store:
        record = fleet.run(pair(tmp_path), store, repo / "runs", pins=pins, launcher=plan)
    assert sorted(plan.launched) == ["poison-server", "reference-server"]
    assert record.problems == []


def test_a_fleet_refused_for_its_destination_says_so_once_and_exits_2(
    tmp_path, monkeypatch, capsys
):
    repo = git_tree(tmp_path / "repo")
    monkeypatch.setattr(fleet, "pin", lambda *_: Pins("runc", "a", "b"))
    store = str(tmp_path / "s.sqlite")
    code = cli.main(["fleet", "run", "--manifest", str(PROJECT), "--store", store,
                     "--out-dir", str(repo / "runs"), "-q"])  # fmt: skip
    said = capsys.readouterr().err
    assert code == cli.EXIT_REFUSED
    assert said.count("git working tree") == 1, said


# -- the least a step may be given ----------------------------------------------------------


@pytest.mark.parametrize("command", ["drive", "fleet"])
@pytest.mark.parametrize("value", ["1.99", "1", "0.5", "1e-300"])
def test_a_step_timeout_below_the_floor_is_refused_when_read(tmp_path, capsys, command, value):
    """The first step includes the server's own start (under runc its container's): measured
    up to 0.89 s with every core busy. Below the floor the setting would decide the run."""
    from mcp_kymograph.driver import MIN_STEP_TIMEOUT

    assert MIN_STEP_TIMEOUT == 2.0
    with pytest.raises(SystemExit) as refused:
        cli.main(argv(command, tmp_path, f"--step-timeout={value}"))
    assert refused.value.code == cli.EXIT_REFUSED
    said = capsys.readouterr().err
    assert "must be at least 2 s" in said and "server's own start" in said, said
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize("value", ["2", "2.0", "30"])
def test_a_step_timeout_at_or_above_the_floor_is_taken(value):
    assert cli.build_parser().parse_args(["drive", "--step-timeout", value]).step_timeout == float(
        value
    )


def test_a_fleet_given_a_step_below_the_floor_refuses_once_before_any_run(tmp_path):
    pins = Pins("runc", "sha256:" + "5a" * 32, "sha256:" + "7a" * 32)

    def must_not_launch(*_args, **_kwargs):
        raise AssertionError("no run may be started")

    with Store.open(tmp_path / "s.sqlite") as store, pytest.raises(FleetError, match="at least 2"):
        fleet.run(PROJECT, store, tmp_path / "runs", pins=pins, step_timeout=1.0,
                  launcher=must_not_launch)  # fmt: skip
    assert not (tmp_path / "runs").exists()
