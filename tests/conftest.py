"""Whether Docker and the sandbox's images are here, decided once for the whole run.

Tests marked ``docker`` need both. Without them they are skipped — never silently: the end of
the run says how many were skipped and why. With ``MCP_KYMOGRAPH_REQUIRE_DOCKER=1`` a missing
Docker is an error in every such test instead: a run that is meant to exercise the sandbox
must not pass by leaving it out.

Tests marked ``real_server`` need the Docker daemon and the images of tests/real_servers (each
test names its own, with the command that builds it), not the sandbox's images. They are skipped
and counted the same way, in a line of their own, and an error under the same variable.

Every test also has a time limit (``MCP_KYMOGRAPH_TEST_TIMEOUT`` seconds, 300 by default, 0 for
none), so a test that hangs fails instead of blocking the suite and CI.
"""

from __future__ import annotations

import faulthandler
import functools
import os
import shutil
import signal
import subprocess
import sys
import threading

import pytest

from mcp_kymograph.environment import helper_env
from mcp_kymograph.sandbox.runner import SANDBOX_IMAGE, TARGET_IMAGE

REQUIRE_DOCKER = "MCP_KYMOGRAPH_REQUIRE_DOCKER"
TEST_TIMEOUT = "MCP_KYMOGRAPH_TEST_TIMEOUT"
_traceback_file = pytest.StashKey[object]()


@functools.cache
def docker_unavailable() -> str | None:
    """Why the Docker tests cannot run here, or None when they can."""
    if shutil.which("docker") is None:
        return "no docker CLI"
    for image in (SANDBOX_IMAGE, TARGET_IMAGE):
        done = subprocess.run(  # noqa: S603
            ["docker", "image", "inspect", image],  # noqa: S607
            capture_output=True,
            env=helper_env(),
            timeout=60,
            check=False,
        )
        if done.returncode != 0:
            detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
            return (
                f"image {image} not usable ({detail[-1] if detail else 'no detail'}); build "
                f"it with: docker build -t {SANDBOX_IMAGE} src/mcp_kymograph/sandbox, and docker "
                f"pull {TARGET_IMAGE}"
            )
    return None


@functools.cache
def daemon_unavailable() -> str | None:
    """Why no container can be started here, or None when the Docker daemon answers."""
    if shutil.which("docker") is None:
        return "no docker CLI"
    try:
        done = subprocess.run(  # noqa: S603
            ["docker", "info"],  # noqa: S607
            capture_output=True,
            env=helper_env(),
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "the Docker daemon does not answer"
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip().splitlines()
        return f"no Docker daemon ({detail[-1] if detail else 'no detail'})"
    return None


def docker_required() -> bool:
    return os.environ.get(REQUIRE_DOCKER) == "1"


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    """Decided before any fixture of the test is set up: a module-scoped fixture that starts a
    sandbox would otherwise try Docker first, and fail for the wrong reason."""
    if item.get_closest_marker("real_server") is not None:
        reason = daemon_unavailable()
        if reason is not None:
            if docker_required():
                pytest.fail(f"{REQUIRE_DOCKER}=1, but {reason}", pytrace=False)
            pytest.skip(reason)
    if item.get_closest_marker("docker") is None:
        return
    reason = docker_unavailable()
    if reason is None:
        return
    if docker_required():
        pytest.fail(f"{REQUIRE_DOCKER}=1, but Docker cannot be used: {reason}", pytrace=False)
    pytest.skip(f"Docker: {reason}")


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ARG001
    """The Docker tests, counted: how many ran, and how many were skipped and why."""
    for marker, label in (("docker", "Docker"), ("real_server", "Real-server")):
        counted = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
        reasons: list[str] = []
        seen = set()
        for outcome in counted:
            for report in terminalreporter.stats.get(outcome, []):
                if marker in getattr(report, "keywords", {}) and report.nodeid not in seen:
                    seen.add(report.nodeid)
                    counted[outcome] += 1
                    if outcome == "skipped" and skip_reason(report) not in reasons:
                        reasons.append(skip_reason(report))
        if not seen:
            continue
        ran = counted["passed"] + counted["failed"]
        line = f"{label} tests: {ran} ran, {counted['skipped']} skipped, {counted['error']} errored"
        if counted["skipped"]:
            why = docker_unavailable() if marker == "docker" else "; ".join(reasons)
            line += f" ({why}); set {REQUIRE_DOCKER}=1 to make that an error"
        terminalreporter.write_line(line, yellow=bool(counted["skipped"]), bold=True)


def skip_reason(report) -> str:
    """The reason a skipped test gave, without pytest's prefix."""
    longrepr = report.longrepr
    text = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr)
    return text.removeprefix("Skipped: ")


def time_limit() -> float:
    """Seconds one test may take; 0 means none, and only the text 0 (or 0.0) says so. Anything
    else must be a number above 0 and at most a day: an error, never silently no limit."""
    text = os.environ.get(TEST_TIMEOUT, "300").strip()
    if text in ("0", "0.0"):
        return 0.0
    try:
        limit = float(text)
    except ValueError:
        limit = float("nan")
    if not 0 < limit <= 86400:
        raise pytest.UsageError(
            f"{TEST_TIMEOUT}={text!r}: expected seconds, above 0, at most 86400"
        )
    return limit


def arm_last_net(config: pytest.Config) -> None:
    """Last net on every platform, for hangs a signal does not interrupt: the whole run ends with
    a traceback after twice the limit. The capture redirects fd 2 during a test, so the traceback
    goes to a copy of it. Armed from the start and again around every test, never switched off,
    so imports, the pauses between tests and threads that outlive the run are covered. Set to 0
    during a run, it is switched off: what was armed before is cancelled first."""
    limit = time_limit()
    faulthandler.cancel_dump_traceback_later()
    if limit:
        faulthandler.dump_traceback_later(2 * limit, exit=True, file=config.stash[_traceback_file])


def pytest_configure(config: pytest.Config) -> None:
    config.stash[_traceback_file] = os.fdopen(os.dup(sys.__stderr__.fileno()), "w")
    arm_last_net(config)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(item: pytest.Item, nextitem):  # noqa: ARG001
    arm_last_net(item.config)
    try:
        return (yield)
    finally:
        arm_last_net(item.config)


@pytest.hookimpl(trylast=True)
def pytest_exception_interact(node: pytest.Item | pytest.Collector) -> None:
    """pytest's faulthandler plugin cancels every timed traceback when a test fails (or is
    stopped by its limit), before the teardown runs; without this the net is off until the
    next test, and a teardown that hangs then hangs for good. Last: after pdb, if one ran."""
    arm_last_net(node.config)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item: pytest.Item):
    """Where SIGALRM exists, a test over the limit fails alone and the suite goes on."""
    limit = time_limit()
    main = threading.current_thread() is threading.main_thread()
    if not (limit and main and hasattr(signal, "SIGALRM")):
        return (yield)

    def expired(signum, frame):  # noqa: ARG001
        raise TimeoutError(f"{item.nodeid} ran over its limit of {limit:g} s ({TEST_TIMEOUT})")

    before = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, limit)
        return (yield)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, before)
