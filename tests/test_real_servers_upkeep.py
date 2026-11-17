"""What the real-server tests leave behind and what they report: no network stands after an HTTP
server that has no image or that does not start, and the stand-in note is one entry per
reference server in the warnings summary of a run."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import test_real_servers as real
from test_real_servers import BUILD, HTTP, LABEL, NONCE, Servers, docker


@pytest.fixture
def servers(tmp_path):
    made = Servers(tmp_path)
    try:
        yield made
    finally:
        made.close()


def networks_of_ours() -> list[str]:
    listed = docker("network", "ls", "--quiet", "--filter", f"label={LABEL}={NONCE}")
    assert listed.returncode == 0, listed.stderr
    return listed.stdout.split()


@pytest.fixture
def no_image(tmp_path, monkeypatch):
    """A tests/real_servers whose images.json has no id for any server."""
    (tmp_path / "images.json").write_text(json.dumps({"other": "sha256:" + "0" * 64}))
    monkeypatch.setattr(real, "REAL", tmp_path)


@pytest.mark.real_server
@pytest.mark.parametrize("required", [False, True], ids=["skipped", "required"])
def test_a_server_without_an_image_gives_the_same_reason_each_time_and_leaves_no_network(
    servers, no_image, monkeypatch, required
):
    monkeypatch.delenv("MCP_KYMOGRAPH_REQUIRE_DOCKER", raising=False)
    if required:
        monkeypatch.setenv("MCP_KYMOGRAPH_REQUIRE_DOCKER", "1")
    outcome = pytest.fail.Exception if required else pytest.skip.Exception
    reasons = []

    for _ in range(2):
        with pytest.raises(outcome) as raised:
            servers.start_http(HTTP[0])
        reasons.append(str(raised.value))

    assert reasons[0] == reasons[1]
    assert BUILD in reasons[0] and HTTP[0] in reasons[0]
    assert networks_of_ours() == []


@pytest.mark.real_server
def test_a_container_that_does_not_start_leaves_no_network(servers, monkeypatch):
    monkeypatch.setattr(real, "image_of", lambda name: "no-such-image")
    # An option docker run does not know: it fails after the network is made, with no pull.
    monkeypatch.setattr(real, "hardened", lambda: ["--no-such-option"])

    for _ in range(2):
        with pytest.raises(AssertionError, match="no-such-option"):
            servers.start_http(HTTP[0])
        assert networks_of_ours() == []


SUMMARY_MODULE = """\
def test_first(servers):
    servers.drive("{name}", engaged=True)


def test_second(servers):
    assert servers.runs
    servers.drive("{name}", engaged=True)
"""
PLUGIN = """\
import pytest
import test_real_servers as real


@pytest.fixture
def servers(tmp_path):
    made = real.Servers(tmp_path)
    for name in real.HTTP:
        # A run already made, so that drive warns and then returns it without Docker.
        made.runs[(name, True, False, False)] = object()
    return made
"""


def test_the_stand_in_note_is_one_entry_per_reference_server_in_the_summary(tmp_path):
    files = {name: f"test_{name.replace('-', '_')}.py" for name in HTTP}
    for name, file in files.items():
        (tmp_path / file).write_text(SUMMARY_MODULE.format(name=name))
    (tmp_path / "stand_in.py").write_text(PLUGIN)
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join([str(Path(__file__).parent), str(tmp_path)]),
        "PYTHONDONTWRITEBYTECODE": "1",
    }

    done = subprocess.run(  # noqa: S603
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "stand_in"]
        + ["-c", os.devnull, "--rootdir", str(tmp_path), str(tmp_path)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=False,
    )

    assert done.returncode == 0, done.stdout + done.stderr
    summary = done.stdout.split("warnings summary", 1)[1]
    assert summary.count("StandInServerWarning:") == len(HTTP), summary
    for name, file in files.items():
        assert summary.count(f"{name}: {real.NO_REFERENCE_SERVER}") == 1, summary
        assert f"{file}::test_first" in summary and f"{file}::test_second" in summary, summary
