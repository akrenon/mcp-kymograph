"""Ctrl-C in a command that has nothing of its own to record: a short line, exit 130 (128 +
SIGINT, as a shell reports a command its SIGINT ended), never a traceback.

``store ingest`` files each recording in a transaction of its own: the one under way when the
interruption comes is rolled back whole, those before it stay filed, and filing again is safe.
A driven run and a fleet are not here: they record their interruption and exit with the state
it left them in (tests/test_fleet_interrupt.py).
"""

from __future__ import annotations

import hashlib
import signal
import subprocess
import sys

from mcp_kymograph import cli
from mcp_kymograph.store import Store
from test_store import finding, recording


def recordings(tmp_path, count: int) -> list[str]:
    return [
        str(recording(tmp_path, [finding(5, statement=f"s{n}")], name=f"run{n}"))
        for n in range(count)
    ]


def filed_runs(database) -> set[str]:
    with Store.open(database) as store:
        return {run.run for run in store.runs()}


def digest(path: str) -> str:
    with open(path, "rb") as file:
        return hashlib.sha256(file.read()).hexdigest()


def test_ctrl_c_in_the_middle_of_filing_a_recording_rolls_it_back_and_says_so(
    tmp_path, monkeypatch, capsys
):
    """The interruption comes inside the second recording's transaction, after its run row was
    written: none of it may stay, the first stays filed, and the line says how far it got."""
    paths = recordings(tmp_path, 3)
    database = tmp_path / "store.sqlite"
    original = Store._file
    calls = []

    def interrupted_in_the_second(self, run, path, parsed):
        calls.append(run)
        original(self, run, path, parsed)
        if len(calls) == 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(Store, "_file", interrupted_in_the_second)
    code = cli.main(["store", "ingest", "--store", str(database), *paths])

    assert code == cli.EXIT_INTERRUPTED == 130
    said = capsys.readouterr().err
    assert "interrupted after 1 of 3 recording(s)" in said
    assert "nothing is half filed" in said
    assert filed_runs(database) == {digest(paths[0])}
    with Store.open(database) as store:
        assert store.findings_of(digest(paths[0]))
        assert not store.findings_of(digest(paths[1])), "no sighting of the rolled-back run"

    monkeypatch.setattr(Store, "_file", original)
    assert cli.main(["store", "ingest", "-q", "--store", str(database), *paths]) == 0
    assert "already filed" in capsys.readouterr().err
    assert filed_runs(database) == {digest(path) for path in paths}


def test_ctrl_c_during_store_ingest_as_a_process_is_a_line_and_130_never_a_traceback(tmp_path):
    """A real SIGINT into a real ingest of many recordings: wherever it lands, the command ends
    with 130 and a line, and what it filed is whole — filing everything again completes it."""
    paths = recordings(tmp_path, 300)
    database = tmp_path / "store.sqlite"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "store", "ingest", "--store", str(database),
         *paths],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )  # fmt: skip
    first = process.stderr.readline()
    assert b"filed" in first, first
    process.send_signal(signal.SIGINT)
    _, rest = process.communicate(timeout=60)
    said = (first + rest).decode()
    assert "Traceback" not in said, said
    assert process.returncode == cli.EXIT_INTERRUPTED, said
    assert "interrupted after" in said, said
    before = filed_runs(database)
    assert 1 <= len(before) < 300, "interrupted somewhere in the middle"

    again = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "store", "ingest", "-q", "--store",
         str(database), *paths],
        capture_output=True, timeout=120, check=False,
    )  # fmt: skip
    assert again.returncode == 0, again.stderr.decode()
    assert filed_runs(database) == {digest(path) for path in paths}


def test_ctrl_c_where_no_command_takes_it_is_a_line_and_130(tmp_path):
    """Before a run or a fleet began, after it was filed, while a store or a manifest was read:
    the command line itself turns the interruption into a line. As a process of its own, so an
    interruption that got through would end it the way a caller sees, not end the test run."""
    script = tmp_path / "interrupted.py"
    script.write_text(
        "import sys\nfrom mcp_kymograph import cli\n"
        "def interrupted(_argv):\n    raise KeyboardInterrupt\n"
        "cli._main = interrupted\nsys.exit(cli.main(['corpus', 'check', 'x']))\n"
    )
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(script)], capture_output=True, timeout=60, check=False
    )
    assert done.returncode == cli.EXIT_INTERRUPTED, done.stderr.decode()
    assert done.stderr == b"kymograph: interrupted\n"
