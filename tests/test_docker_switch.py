"""The Docker tests are never skipped silently, and under the switch not at all.

Run in a pytest of their own, with no ``docker`` on the PATH, so the outcome does not depend on
whether this machine has Docker: without MCP_KYMOGRAPH_REQUIRE_DOCKER the Docker tests are skipped
and the end of the run counts them; with it set to 1 each of them is an error.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
#: Two Docker tests from two files, marked in the two ways the suite marks them.
DOCKER_TESTS = (
    "tests/test_sandbox_runc.py::test_helper_exits_zero",
    "tests/test_fleet.py::test_the_pair_holds_over_the_stack",
)


#: What turns colour on or off in pytest, in Python itself and in the tools they defer to. The
#: inner run's output is read as text, so none of them may reach it from the outer environment.
COLOUR_VARIABLES = frozenset(
    {"FORCE_COLOR", "PY_COLORS", "NO_COLOR", "PYTHON_COLORS", "CLICOLOR", "CLICOLOR_FORCE"}
)
#: Also what an outer environment could hand the inner pytest as options: colour among them.
NOT_PASSED_ON = (
    frozenset({"MCP_KYMOGRAPH_REQUIRE_DOCKER", "PATH", "PYTEST_ADDOPTS"}) | COLOUR_VARIABLES
)


def inner_environment(**env: str) -> dict[str, str]:
    environment = {k: v for k, v in os.environ.items() if k not in NOT_PASSED_ON}
    environment.update(PATH=str(ROOT / "no-such-directory"), **env)
    return environment


def run_without_docker(**env: str) -> subprocess.CompletedProcess[str]:
    # --color=no on top of the cleaned environment: pytest gives the option precedence over
    # every variable, so the output stays plain even for a variable passed in on purpose.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-o", "addopts=", "-q", "-rs", "-p", "no:cacheprovider",
         "--color=no", *DOCKER_TESTS],
        cwd=ROOT, env=inner_environment(**env), capture_output=True, text=True, timeout=300,
        check=False,
    )  # fmt: skip


def test_without_the_switch_a_missing_docker_skips_and_the_run_says_how_many():
    done = run_without_docker()
    assert done.returncode == 0, done.stdout + done.stderr
    assert "2 skipped" in done.stdout
    assert (
        "Docker tests: 0 ran, 2 skipped, 0 errored (no docker CLI); set "
        "MCP_KYMOGRAPH_REQUIRE_DOCKER=1 to make that an error"
    ) in done.stdout


def test_with_the_switch_a_missing_docker_is_an_error_in_every_docker_test():
    done = run_without_docker(MCP_KYMOGRAPH_REQUIRE_DOCKER="1")
    assert done.returncode == 1, done.stdout + done.stderr
    assert done.stdout.strip().splitlines()[-1].startswith("2 errors in ")
    assert (
        done.stdout.count(
            "MCP_KYMOGRAPH_REQUIRE_DOCKER=1, but Docker cannot be used: no docker CLI"
        )
        >= 2
    )
    assert "Docker tests: 0 ran, 0 skipped, 2 errored" in done.stdout


def test_the_outer_colour_settings_do_not_reach_the_inner_run(monkeypatch):
    for name in COLOUR_VARIABLES:
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--color=yes")
    environment = inner_environment(MCP_KYMOGRAPH_REQUIRE_DOCKER="1")
    assert not COLOUR_VARIABLES & environment.keys()
    assert "PYTEST_ADDOPTS" not in environment
    assert environment["MCP_KYMOGRAPH_REQUIRE_DOCKER"] == "1"


@pytest.mark.parametrize("variable", ["FORCE_COLOR", "PY_COLORS"])
def test_with_colour_forced_outside_the_switch_still_reads_the_same(monkeypatch, variable):
    # The way this test used to fail: a terminal or CI that forces colour for everything.
    monkeypatch.setenv(variable, "1")
    test_with_the_switch_a_missing_docker_is_an_error_in_every_docker_test()


def test_colour_forced_into_the_inner_run_itself_still_leaves_it_plain():
    # Past the cleaned environment, on purpose: what keeps the output plain here is the option.
    done = run_without_docker(MCP_KYMOGRAPH_REQUIRE_DOCKER="1", FORCE_COLOR="1", PY_COLORS="1")
    assert "\x1b[" not in done.stdout + done.stderr
    assert done.stdout.strip().splitlines()[-1].startswith("2 errors in ")
