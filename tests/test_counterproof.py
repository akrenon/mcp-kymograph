"""The counter-proof: run the poisoning rule against a vulnerable and a hardened target and
lay both recordings down for a human to judge.

This test prepares evidence. It does not decide whether the finding is valid — that is the
human's call, from the two recordings it lays down. So it asserts only that both runs
completed and produced a readable recording with the intervention in it; it makes no claim
about whether the vulnerable target obeyed and the hardened one did not.

Where the recordings go: into the test's own temporary directory, gone with it, unless
``MCP_KYMOGRAPH_COUNTERPROOF_DIR`` names a directory to keep them in.
"""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph.engine import Engine
from mcp_kymograph.masking import Masker
from mcp_kymograph.proxy import Limits, Proxy
from mcp_kymograph.recorder import Recorder
from mcp_kymograph.rules import ToolPoisoning

FIXTURES = Path(__file__).parent / "fixtures"
TOY = str(FIXTURES / "toy_server.py")
TARGET = str(FIXTURES / "poisoning_target.py")
#: The directory to keep the two recordings in for a human to judge. Unset or empty, they are
#: laid down in the test's temporary directory and nothing outside it is written.
COUNTERPROOF_DIR = "MCP_KYMOGRAPH_COUNTERPROOF_DIR"


def lay_down(mode: str, recording: Path, tmp_path: Path) -> Path:
    """Copy one recording to where the human reads it; return where that is."""
    chosen = os.environ.get(COUNTERPROOF_DIR)
    directory = Path(chosen) if chosen else tmp_path / "counterproof"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{mode}.jsonl"
    target.write_text(recording.read_text())
    return target


async def _run_one(mode: str, recording: Path) -> int:
    """Drive target ⇄ proxy(engine) ⇄ toy-server for one mode; return the target's exit code."""
    target = subprocess.Popen(  # noqa: S603
        [sys.executable, TARGET, "--mode", mode],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    limits = Limits(
        max_duration_seconds=30.0, terminate_grace_seconds=0.5, shutdown_budget_seconds=3.0
    )
    with Recorder.open(recording, run_id=f"gegenbeweis-{mode}", masker=Masker()) as recorder:
        proxy = Proxy(
            argv=[sys.executable, TOY, "--mode", "normal"],
            recorder=recorder,
            limits=limits,
            client_in=target.stdout,
            client_out=target.stdin,
            engine=Engine([ToolPoisoning()]),
        )
        await proxy.run()
    try:
        return target.wait(timeout=5)
    except subprocess.TimeoutExpired:
        target.kill()
        return -1


@pytest.mark.parametrize("mode", ["vulnerable", "hardened"])
def test_counterproof_produces_a_readable_recording(mode, tmp_path):
    recording = tmp_path / f"{mode}.jsonl"
    exit_code = asyncio.run(_run_one(mode, recording))
    assert exit_code == 0, f"the {mode} target must complete its short conversation"

    events = [json.loads(line) for line in recording.read_text().splitlines()]
    assert events[0]["type"] == "run_started"
    assert events[-1]["type"] == "run_finished"
    assert any(e["type"] == "intervention" for e in events), "the rule must have fired"

    # Lay the artifact down for the human. This test states no verdict on what it shows.
    lay_down(mode, recording, tmp_path)


def test_without_the_variable_the_recording_stays_in_the_test_directory(tmp_path, monkeypatch):
    monkeypatch.delenv(COUNTERPROOF_DIR, raising=False)
    recording = tmp_path / "run.jsonl"
    recording.write_text('{"type": "run_started"}\n')
    target = lay_down("vulnerable", recording, tmp_path)
    assert target == tmp_path / "counterproof" / "vulnerable.jsonl"
    assert target.read_text() == recording.read_text()
    monkeypatch.setenv(COUNTERPROOF_DIR, "")
    assert lay_down("hardened", recording, tmp_path).parent == tmp_path / "counterproof"


def test_with_the_variable_the_recording_goes_where_it_says(tmp_path, monkeypatch):
    keep = tmp_path / "kept" / "for-a-human"
    monkeypatch.setenv(COUNTERPROOF_DIR, str(keep))
    recording = tmp_path / "run.jsonl"
    recording.write_text('{"type": "run_started"}\n')
    target = lay_down("hardened", recording, tmp_path)
    assert target == keep / "hardened.jsonl"
    assert target.read_text() == recording.read_text()
    assert not (tmp_path / "counterproof").exists()
