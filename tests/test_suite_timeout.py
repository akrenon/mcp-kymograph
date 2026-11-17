"""The time limit of one test (tests/conftest.py), exercised in a pytest run of its own."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

posix_only = pytest.mark.skipif(not hasattr(signal, "SIGALRM"), reason="needs SIGALRM")

HANGING = """
    import time

    def test_hangs():
        time.sleep(60)

    def test_next():
        pass

    def test_fast():
        time.sleep(0.01)
"""


def run_pytest(tmp_path, source: str, limit: str, *args: str):
    (tmp_path / "test_inner.py").write_text(textwrap.dedent(source))
    shutil.copy(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    env = {**os.environ, "MCP_KYMOGRAPH_TEST_TIMEOUT": limit, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@posix_only
def test_hanging_test_fails_and_the_next_one_runs(tmp_path):
    done = run_pytest(tmp_path, HANGING, "1")
    assert done.returncode == 1, done.stdout + done.stderr
    assert "1 failed, 2 passed" in done.stdout
    assert "test_inner.py::test_hangs ran over its limit of 1 s" in done.stdout
    assert "MCP_KYMOGRAPH_TEST_TIMEOUT" in done.stdout


def test_fast_tests_stay_green(tmp_path):
    done = run_pytest(tmp_path, HANGING.replace("60", "0.01"), "5")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "3 passed" in done.stdout


@posix_only
def test_zero_switches_it_off(tmp_path):
    source = """
        import signal
        import time

        def test_no_alarm():
            assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
            assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
            time.sleep(1.5)
    """
    done = run_pytest(tmp_path, source, "0")
    assert done.returncode == 0, done.stdout + done.stderr


@posix_only
def test_alarm_is_reset_after_a_failing_test(tmp_path):
    source = """
        import signal
        import pytest

        @pytest.fixture
        def alarm_off_afterwards():
            before = signal.getsignal(signal.SIGALRM)
            yield
            assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
            assert signal.getsignal(signal.SIGALRM) == before

        def test_fails(alarm_off_afterwards):
            raise AssertionError("own failure")
    """
    done = run_pytest(tmp_path, source, "30")
    assert "1 failed in" in done.stdout, done.stdout + done.stderr
    assert "error" not in done.stdout


def test_a_hang_in_setup_ends_the_run_with_a_traceback(tmp_path):
    source = """
        import time
        import pytest

        @pytest.fixture
        def stuck():
            time.sleep(60)

        def test_never(stuck):
            pass
    """
    done = run_pytest(tmp_path, source, "1")
    assert done.returncode != 0
    assert "most recent call first" in done.stderr
    assert "in stuck" in done.stderr


@pytest.mark.parametrize("bad", ["soon", "-1", "nan", "-0", "1e-400", "1e10", "inf", ""])
def test_a_value_that_is_not_seconds_is_an_error(tmp_path, bad):
    source = "import time\n\ndef test_x():\n    time.sleep(30)\n"
    done = run_pytest(tmp_path, source, bad)
    assert done.returncode != 0, done.stdout + done.stderr
    assert "MCP_KYMOGRAPH_TEST_TIMEOUT" in done.stderr + done.stdout


def ends_with_traceback(tmp_path, source, limit="1"):
    """The run ends with a traceback, and within about twice the limit: the net, not the outer
    timeout of the run, ended it (an interpreter start besides)."""
    started = time.monotonic()
    done = run_pytest(tmp_path, source, limit)
    assert time.monotonic() - started < 2 * float(limit) + 10, "the net came late"
    assert done.returncode != 0, done.stdout + done.stderr
    assert "most recent call first" in done.stderr, done.stderr


def test_a_thread_that_outlives_the_run_ends_it_with_a_traceback(tmp_path):
    source = """
        import threading

        def test_green():
            threading.Thread(target=threading.Event().wait).start()
    """
    ends_with_traceback(tmp_path, source)


def test_a_hang_at_import_ends_the_run_with_a_traceback(tmp_path):
    ends_with_traceback(tmp_path, "import time\n\ntime.sleep(3600)\n")


def test_switching_it_off_during_the_run_cancels_the_net(tmp_path):
    """Found in review: set to 0 by one test, the net armed before must not end a later one."""
    source = """
        import os, time

        def test_turn_it_off():
            os.environ["MCP_KYMOGRAPH_TEST_TIMEOUT"] = "0"

        def test_slow_but_healthy():
            time.sleep(3)
    """
    done = run_pytest(tmp_path, source, "1")
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize(
    "call",
    [
        pytest.param("raise AssertionError('own failure')", id="failed"),
        # Without SIGALRM the test is not stopped at its limit: the net would end the run in
        # the test itself, and the variant would pass without reaching the teardown.
        pytest.param("time.sleep(60)", id="over its limit", marks=posix_only),
    ],
)
def test_a_hang_in_the_teardown_of_a_failed_test_ends_the_run_with_a_traceback(tmp_path, call):
    """Found in a run that hung for good: pytest's faulthandler plugin switches the net off when
    a test fails (``pytest_exception_interact``), and the teardown after it ran without one."""
    source = f"""
        import time
        import pytest

        @pytest.fixture
        def stuck_afterwards():
            yield
            time.sleep(3600)

        def test_fails(stuck_afterwards):
            {call}
    """
    ends_with_traceback(tmp_path, source)
