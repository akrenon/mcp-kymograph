"""A result that cannot be written to stdout is never lost in silence.

A closed stdout (the process started with descriptor 1 closed) or a pipe whose reader has gone
is a write error: the command ends with 74 (EX_IOERR) and says on stderr that its result was not
written and what its exit status would have been — no traceback, no complaint from the
interpreter at exit. A proxied run, whose stdout is the client's channel, is refused before
anything starts when there is none.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, fleet
from mcp_kymograph.store import Store
from test_fleet import PINS, launcher, pair
from test_store import recording

PROJECT = Path(__file__).parent / "fixtures" / "corpus" / "manifest.yaml"
TOY = str(Path(__file__).parent / "fixtures" / "toy_server.py")


@pytest.fixture
def store_with_a_fleet(tmp_path) -> Path:
    database = tmp_path / "s.sqlite"
    with Store.open(database) as store:
        for _ in range(2):
            fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                      launcher=launcher({"reference-server": {}, "poison-server": {}}))  # fmt: skip
        store.ingest(recording(tmp_path, [], name="one"))
        store.ingest(recording(tmp_path, [], name="two", tool_content="sha256:" + "12" * 32))
    return database


def commands(database: Path, tmp_path: Path) -> dict[str, tuple[list[str], int]]:
    """Every command that answers with JSON on stdout, and its exit status when it can."""
    events = recording(tmp_path, [], name="judged")
    return {
        "verdict": (["verdict", str(events)], 0),
        "corpus check": (["corpus", "check", str(PROJECT)], 0),
        "store runs": (["store", "runs", "--store", str(database)], 0),
        "store findings": (["store", "findings", "--store", str(database), "--provenance",
                            "poison"], 0),
        "fleet runs": (["fleet", "runs", "--store", str(database)], 0),
        "fleet diff": (["fleet", "diff", "--store", str(database)], 0),
        "store diff": (["store", "diff", "--store", str(database), str(tmp_path / "one.jsonl"),
                        str(tmp_path / "two.jsonl")], 0),
    }  # fmt: skip


def run_with_stdout(args: list[str], how: str) -> subprocess.CompletedProcess:
    argv = [sys.executable, "-m", "mcp_kymograph.cli", *args]
    if how == "closed":
        return subprocess.run(  # noqa: S603
            argv,
            capture_output=False,
            stderr=subprocess.PIPE,
            preexec_fn=lambda: os.close(1),  # noqa: PLW1509 - the point of the test
            timeout=60,
            check=False,
        )
    read, write = os.pipe()
    os.close(read)  # the reader is gone before anything is written
    try:
        return subprocess.run(  # noqa: S603
            argv, stdout=write, stderr=subprocess.PIPE, timeout=60, check=False
        )
    finally:
        os.close(write)


@pytest.mark.parametrize("how", ["closed", "broken-pipe"])
@pytest.mark.parametrize(
    "name",
    [
        "verdict",
        "corpus check",
        "store runs",
        "store findings",
        "fleet runs",
        "fleet diff",
        "store diff",
    ],
)
def test_a_result_that_cannot_be_written_is_an_error_with_its_own_exit_and_a_line(
    tmp_path, store_with_a_fleet, name, how
):
    args, own = commands(store_with_a_fleet, tmp_path)[name]
    done = run_with_stdout(args, how)
    said = done.stderr.decode()
    assert done.returncode == cli.EXIT_OUTPUT_FAILED == 74, said
    assert "the result could not be written to stdout" in said
    assert f"the exit status is 74 instead of {own}" in said
    assert "Traceback" not in said and "Exception ignored" not in said, said


def test_the_work_is_done_even_when_its_result_cannot_be_written(tmp_path, monkeypatch, capsys):
    """The store is still written to; only the JSON is lost — and that is said."""

    class Broken(io.StringIO):
        def write(self, _text):
            raise BrokenPipeError(32, "Broken pipe")

        def fileno(self):
            raise OSError("no descriptor")

    database = tmp_path / "s.sqlite"
    path = recording(tmp_path, [], name="filed")
    assert cli.main(["store", "ingest", "-q", "--store", str(database), str(path)]) == 0
    monkeypatch.setattr(sys, "stdout", Broken())
    assert cli.main(["store", "runs", "--store", str(database)]) == cli.EXIT_OUTPUT_FAILED
    assert "(Broken pipe); it is lost" in capsys.readouterr().err
    with Store.open(database) as store:
        assert len(store.runs()) == 1


def test_the_next_command_in_the_same_process_starts_with_a_clean_slate(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdout", None)
    assert cli.main(["corpus", "check", str(PROJECT)]) == cli.EXIT_OUTPUT_FAILED
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert cli.main(["corpus", "check", str(PROJECT)]) == 0
    assert json.loads(sys.stdout.getvalue())["entries"]


def test_a_proxied_run_without_a_stdout_is_refused_before_anything_starts(tmp_path):
    out = tmp_path / "runs"
    marker = tmp_path / "server-started"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "run", "-q", "--out-dir", str(out), "--",
         sys.executable, "-c", f"open({str(marker)!r}, 'w')"],
        stdin=subprocess.DEVNULL, stderr=subprocess.PIPE,
        preexec_fn=lambda: os.close(1),  # noqa: PLW1509 - the point of the test
        timeout=60, check=False,
    )  # fmt: skip
    said = done.stderr.decode()
    assert done.returncode == cli.EXIT_REFUSED, said
    assert "stdout is closed: there is no channel to the client" in said
    assert "Traceback" not in said
    assert not out.exists() and not marker.exists()


def test_a_driven_run_needs_no_stdout(tmp_path):
    """The other direction: drive writes nothing to stdout, so a closed one costs it nothing."""
    out = tmp_path / "runs"
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "drive", "-q", "--out-dir", str(out), "--",
         sys.executable, str(Path(__file__).parent / "fixtures" / "discovery_server.py")],
        stdin=subprocess.DEVNULL, stderr=subprocess.PIPE,
        preexec_fn=lambda: os.close(1),  # noqa: PLW1509 - the point of the test
        timeout=60, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stderr.decode()
