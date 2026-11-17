"""Pacing: the slots of an origin under ``<out-dir>/.pacing/``, the interval between two runs, the
wait that is refused, and what the recording says of both.

The core is tested with an injectable clock; the runs through ``cli.main`` go to the fixture
server over TLS on loopback under the name ``localhost``, which is not a loopback literal and so
is paced, with the test CA as the machine's trust store (``tests/fixtures/tls``). No test
connects beyond loopback.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import io
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import textwrap
import threading
import time
import types
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, identity_compare, pacing, proxy, verdict
from mcp_kymograph.events import HTTP_SSE_ONLY, HTTP_STATUS
from mcp_kymograph.http_client import HttpClientChannel
from mcp_kymograph.pacing import Pacing, PacingRefused
from test_active_probes import probing
from test_cli_engagement import events_of, refusals_in, write_engagement
from test_engagement import write
from test_http_client import drive, http, stub
from test_http_tls import TRUSTED, http_server, serve, trust_ca  # noqa: F401

__all__ = ["serve", "stub", "trust_ca"]

URL = "https://customer.example.test/mcp"


class Time:
    """A clock that sleeps by moving itself on."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def slot_files(out_dir) -> list[Path]:
    """The slot files, not the origins' locks (``<digest>.lock``)."""
    return sorted((Path(out_dir) / ".pacing").glob("*.[0-9].lock"))


def take(out_dir, time_, *, url=URL, pacing_=None, step_timeout=30.0):
    return pacing.acquire(
        out_dir,
        url,
        pacing_ or pacing.settings(None),
        step_timeout,
        clock=time_,
        sleep=time_.sleep,
    )


# -- the values and the origin ---------------------------------------------------------------


def test_the_values_are_the_files_where_it_speaks_and_1_and_10_where_it_does_not():
    assert pacing.settings(None) == Pacing(1, 10, "default", ())
    assert pacing.settings({}).source == "default"
    only = pacing.settings({"min_interval_seconds": 2.5})
    assert (only.runs_per_origin, only.min_interval_seconds, only.source) == (1, 2.5, "file")
    assert only.from_file == ("min_interval_seconds",)
    both = pacing.settings({"runs_per_origin": 3, "min_interval_seconds": 0})
    assert both.as_dict() == {"runs_per_origin": 3, "min_interval_seconds": 0, "source": "file"}


@pytest.mark.parametrize(
    ("url", "paced"),
    [
        ("https://customer.example.test/mcp", True),
        ("https://localhost:8443/mcp", True),
        ("http://127.0.0.2:8080/mcp", True),
        ("http://127.0.0.1:8080/mcp", False),
        ("http://[::1]:8080/mcp", False),
        (None, False),
    ],
)
def test_only_a_host_that_is_not_a_loopback_literal_is_paced(url, paced):
    assert pacing.applies(url) is paced


def test_the_origin_is_scheme_host_and_port_with_the_schemes_own_port_filled_in():
    assert pacing.origin_of("HTTPS://Customer.Example.test/mcp?a=1") == (
        "https://customer.example.test:443"
    )
    assert pacing.origin_of("http://customer.example.test/x") == "http://customer.example.test:80"
    assert pacing.origin_of("https://[2001:db8::1]:8443/") == "https://[2001:db8::1]:8443"


# -- the slots -------------------------------------------------------------------------------


def test_the_directory_is_private_and_a_slot_is_one_private_file_per_origin_and_number(tmp_path):
    clock = Time()
    with take(tmp_path, clock):
        pass
    directory = tmp_path / ".pacing"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    (lock,) = slot_files(tmp_path)
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    assert lock.name.endswith(".0.lock") and len(lock.name) == 64 + len(".0.lock")
    (origin,) = directory.glob("*[!0-9].lock")  # the short lock of the origin, no slot
    assert origin.name == f"{lock.name.split('.')[0]}.lock"
    assert stat.S_IMODE(origin.stat().st_mode) == 0o600
    assert float(lock.read_text()) == clock.now, "the end of the run is written on release"


def test_a_run_that_finds_the_origin_idle_and_never_run_does_not_wait(tmp_path):
    clock = Time()
    with take(tmp_path, clock) as slot:
        assert slot.paced is None
    assert clock.slept == []


def test_the_second_run_waits_out_the_interval_and_says_so(tmp_path):
    clock = Time()
    with take(tmp_path, clock):
        clock.now += 3  # the first run takes three seconds
    clock.now += 4  # and the operator takes four to start the next
    with take(tmp_path, clock) as slot:
        assert slot.paced is not None
        assert slot.paced.why == "interval"
        assert slot.paced.seconds >= 10 - 4 - 0.5, "the interval, less the clock's slack"
        assert slot.paced.seconds == pytest.approx(6.0)


def test_an_interval_that_has_passed_costs_nothing(tmp_path):
    clock = Time()
    with take(tmp_path, clock):
        pass
    clock.now += 10.5
    with take(tmp_path, clock) as slot:
        assert slot.paced is None


def test_the_interval_is_measured_from_the_latest_end_among_the_slots(tmp_path):
    clock = Time()
    settings = Pacing(runs_per_origin=2, min_interval_seconds=10)
    first = take(tmp_path, clock, pacing_=settings)
    second = take(tmp_path, clock, pacing_=settings)  # the second slot, while the first is held
    first.release()  # ends at 1_000_000
    clock.now += 5
    second.release()  # ends later, at 1_000_005
    third = take(tmp_path, clock, pacing_=settings)
    assert third.paced is not None and third.paced.seconds == pytest.approx(10.0)
    third.release()


def test_a_wait_over_the_step_timeout_is_refused_and_the_slot_is_let_go(tmp_path):
    clock = Time()
    with take(tmp_path, clock):
        pass
    with pytest.raises(PacingRefused, match="--step-timeout"):
        take(tmp_path, clock, step_timeout=5.0)
    assert clock.slept == [], "a refused run waits for nothing"
    with take(tmp_path, clock, step_timeout=30.0) as slot:  # the lock was not kept
        assert slot.paced is not None


def test_a_busy_origin_is_waited_for_and_the_run_that_waited_says_origin_busy(tmp_path):
    clock = Time()
    held = take(tmp_path, clock)
    polls = []

    def let_go_after_three_polls(seconds: float) -> None:
        clock.sleep(seconds)
        polls.append(seconds)
        if len(polls) == 3:
            held.release()

    with pacing.acquire(
        tmp_path, URL, Pacing(1, 0), 30.0, clock=clock, sleep=let_go_after_three_polls
    ) as slot:
        assert slot.paced is not None and slot.paced.why == "origin_busy"
        assert slot.paced.seconds == pytest.approx(3 * pacing.POLL_SECONDS)


def test_a_busy_origin_that_stays_busy_is_refused_at_the_step_timeout(tmp_path):
    clock = Time()
    held = take(tmp_path, clock)
    with pytest.raises(PacingRefused, match="in use"):
        take(tmp_path, clock, step_timeout=2.0)
    assert 2.0 <= clock.now - 1_000_000.0 < 2.0 + 2 * pacing.POLL_SECONDS
    held.release()


def test_another_origin_has_slots_of_its_own(tmp_path):
    clock = Time()
    with (
        take(tmp_path, clock),
        take(tmp_path, clock, url="https://other.example.test/mcp") as slot,
    ):
        assert slot.paced is None


def test_runs_per_origin_is_how_many_may_hold_a_slot_at_once(tmp_path):
    clock = Time()
    settings = Pacing(runs_per_origin=2, min_interval_seconds=0)
    first = take(tmp_path, clock, pacing_=settings)
    second = take(tmp_path, clock, pacing_=settings)
    assert first.paced is None and second.paced is None
    with pytest.raises(PacingRefused):
        take(tmp_path, clock, pacing_=settings, step_timeout=0.5)
    first.release()
    second.release()


# -- two processes ---------------------------------------------------------------------------

#: Takes the origin's slot, writes when it got it and when it let go, and holds it for 0.8 s.
PROCESS = textwrap.dedent(
    """
    import sys, time
    from mcp_kymograph import pacing
    out_dir, name = sys.argv[1], sys.argv[2]
    slot = pacing.acquire(out_dir, "https://customer.example.test/mcp", pacing.Pacing(1, 0), 20)
    began = time.time()
    time.sleep(0.8)
    ended = time.time()
    slot.release()
    why = slot.paced.why if slot.paced else None
    open(f"{out_dir}/{name}.json", "w").write(repr((began, ended, why)))
    """
)


def test_two_processes_on_one_origin_run_one_after_the_other(tmp_path):
    command = [sys.executable, "-I", "-c", PROCESS, str(tmp_path)]
    first = subprocess.Popen([*command, "first"])  # noqa: S603
    time.sleep(0.3)  # the first has the slot by now
    second = subprocess.Popen([*command, "second"])  # noqa: S603
    assert first.wait(timeout=30) == 0
    assert second.wait(timeout=30) == 0
    began_first, ended_first, why_first = eval((tmp_path / "first.json").read_text())  # noqa: S307
    began_second, _, why_second = eval((tmp_path / "second.json").read_text())  # noqa: S307
    assert why_first is None
    assert why_second == "origin_busy"
    assert began_second >= ended_first, "the second began only after the first had let go"
    assert began_first < ended_first


#: Takes the slot, says so, and waits to be killed.
HOLDER = textwrap.dedent(
    """
    import sys, time
    from mcp_kymograph import pacing
    slot = pacing.acquire(sys.argv[1], "https://customer.example.test/mcp", pacing.Pacing(1, 0), 20)
    print("held", flush=True)
    time.sleep(60)
    """
)


def killed_holder(out_dir) -> None:
    child = subprocess.Popen(  # noqa: S603
        [sys.executable, "-I", "-c", HOLDER, str(out_dir)], stdout=subprocess.PIPE, text=True
    )
    try:
        assert child.stdout.readline().strip() == "held"
        child.kill()  # SIGKILL: release() never runs
    finally:
        child.wait(timeout=30)


def test_a_run_that_was_killed_counts_as_ended_when_the_next_run_finds_it(tmp_path):
    with take(tmp_path, Time(start=time.time() - 3600)):
        pass  # an old end time, long past the interval: the killed run must not leave this behind
    killed_holder(tmp_path)
    clock = Time(start=time.time())

    with take(tmp_path, clock) as slot:
        assert slot.paced is not None and slot.paced.why == "interval"
        assert slot.paced.seconds == pytest.approx(10.0)
    assert clock.slept == [pytest.approx(10.0)], "the full interval, from the moment it was found"


def test_a_start_note_is_in_the_slot_while_it_is_held_and_an_end_time_after(tmp_path):
    clock = Time()
    with take(tmp_path, clock):
        (lock,) = slot_files(tmp_path)
        assert lock.read_text().startswith(pacing.START_NOTE)
    assert float(lock.read_text()) == clock.now


def test_a_refused_run_leaves_the_slot_as_it_found_it(tmp_path):
    clock = Time()
    with take(tmp_path, clock):
        pass
    (lock,) = slot_files(tmp_path)
    ended = lock.read_text()
    with pytest.raises(PacingRefused):
        take(tmp_path, clock, step_timeout=5.0)
    assert lock.read_text() == ended


def test_a_held_slot_counts_with_the_end_time_its_note_carries(tmp_path):
    """Run X ended at t=0 in slot 0; B takes slot 0 (its note says ``after`` 0); A takes slot 1,
    which holds an old end, and must not connect at once."""
    clock = Time()
    settings = Pacing(runs_per_origin=2, min_interval_seconds=10)
    with take(tmp_path, clock, pacing_=settings):
        pass  # X: ends at 1_000_000, in slot 0
    (slot_zero, slot_one) = slot_files(tmp_path)
    slot_one.write_text(f"{clock.now - 500!r}\n")  # an old end, long past the interval
    clock.now += 1
    b = take(tmp_path, clock, pacing_=settings)  # slot 0, the interval has 9 s to go
    assert b.paced is not None and b.paced.seconds == pytest.approx(9.0)
    assert "after 1000000.0" in slot_zero.read_text()
    clock.now = 1_000_001.5
    a = take(tmp_path, clock, pacing_=settings)  # slot 1, slot 0 held by B
    assert a.paced is not None and a.paced.why == "interval"
    assert clock.now == pytest.approx(1_000_010.0), "A waited until t=10 after X's end"
    a.release()
    b.release()


def test_a_held_slot_with_no_end_before_it_adds_nothing_to_the_wait(tmp_path):
    clock = Time()
    settings = Pacing(runs_per_origin=2, min_interval_seconds=10)
    going = take(tmp_path, clock, pacing_=settings)  # the origin never ran: "after none"
    other = take(tmp_path, clock, pacing_=settings)
    assert going.paced is None and other.paced is None
    going.release()
    other.release()


def test_a_dead_note_that_another_run_takes_over_is_still_counted_by_a_run_that_reads(tmp_path):
    """B takes the slot of a run that was killed and waits the interval from the moment it found
    the note; A, reading while B waits, finds the slot held and waits the same."""
    clock = Time(start=time.time())
    settings = Pacing(runs_per_origin=2, min_interval_seconds=10)
    killed_holder(tmp_path)  # slot 0: a start note, nobody holds it
    arrived: list[pacing.Slot] = []

    def while_b_waits(seconds: float) -> None:
        arrived.append(take(tmp_path, clock, pacing_=settings))  # A, with the clock still at B's
        clock.sleep(seconds)

    b = pacing.acquire(tmp_path, URL, settings, 30.0, clock=clock, sleep=while_b_waits)
    (a,) = arrived
    assert b.paced is not None and a.paced is not None
    assert a.paced.why == "interval" and a.paced.seconds == pytest.approx(10.0)
    a.release()
    b.release()


def test_slots_are_read_and_written_under_the_origin_lock_and_not_while_waiting(
    tmp_path, monkeypatch
):
    """Every write of a note and of a put-back happens with the origin's lock held by this run;
    the wait of the interval does not."""
    clock = Time()
    directory = tmp_path / ".pacing"
    held_at_write: list[bool] = []
    held_at_sleep: list[bool] = []
    real_write = pacing._write

    def origin_locked() -> bool:
        (origin,) = directory.glob("*[!0-9].lock")
        probe = os.open(origin, os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        finally:
            os.close(probe)
        return False

    def watching_write(descriptor: int, text: str) -> None:
        held_at_write.append(origin_locked())
        real_write(descriptor, text)

    def watching_sleep(seconds: float) -> None:
        held_at_sleep.append(origin_locked())
        clock.sleep(seconds)

    with take(tmp_path, clock):
        pass
    monkeypatch.setattr(pacing, "_write", watching_write)
    with pacing.acquire(
        tmp_path, URL, Pacing(1, 10), 30.0, clock=clock, sleep=watching_sleep
    ):  # the note, then the wait
        monkeypatch.setattr(pacing, "_write", real_write)
    monkeypatch.setattr(pacing, "_write", watching_write)
    with pytest.raises(PacingRefused):  # the note, then the put-back
        pacing.acquire(tmp_path, URL, Pacing(1, 10), 1.0, clock=clock, sleep=watching_sleep)

    assert held_at_write == [True, True, True]
    assert held_at_sleep == [False]


def test_a_refused_run_puts_a_dead_note_back_as_its_end_for_the_next_run(tmp_path):
    clock = Time(start=time.time())
    killed_holder(tmp_path)
    with pytest.raises(PacingRefused):
        take(tmp_path, clock, step_timeout=5.0)
    (lock,) = slot_files(tmp_path)
    assert float(lock.read_text()) == clock.now, "found, so the next run waits from there"
    with take(tmp_path, clock) as slot:
        assert slot.paced is not None and slot.paced.seconds == pytest.approx(10.0)


def test_while_a_run_is_refused_another_run_still_sees_the_end_time_the_slot_held(tmp_path):
    """R holds slot 0, which held the end E, and must wait; while it waits, S takes slot 1 and
    waits until E + 10. R is then refused and puts E back in slot 0."""
    clock = Time()
    settings = Pacing(runs_per_origin=2, min_interval_seconds=10)
    with take(tmp_path, clock, pacing_=settings):
        pass
    (slot_zero, _) = slot_files(tmp_path)
    ended = clock.now  # E
    clock.now += 1
    arrived: list[pacing.Slot] = []

    def while_r_waits(seconds: float) -> None:
        arrived.append(take(tmp_path, clock, pacing_=settings))  # S, slot 1, slot 0 held by R
        raise PacingRefused("R is refused while S waits")

    with pytest.raises(PacingRefused, match="while S waits"):
        pacing.acquire(tmp_path, URL, settings, 30.0, clock=clock, sleep=while_r_waits)
    (s,) = arrived
    assert s.paced is not None and s.paced.why == "interval"
    assert s.paced.seconds == pytest.approx(9.0)
    assert clock.now == pytest.approx(ended + 10), "S waited until E + 10, not from its own start"
    assert float(slot_zero.read_text()) == ended, "R put E back"
    s.release()


def test_a_run_that_reads_the_slots_is_not_seen_by_another_as_a_run_holding_one(
    tmp_path, monkeypatch
):
    """Run A holds slot 0 and is looking at slot 1 (locking it to see whether it is free); run B
    comes then. B waits for the origin lock instead of finding slot 1 locked, takes it once A is
    done, and does not wait for ``origin_busy``."""
    settings = Pacing(runs_per_origin=2, min_interval_seconds=0)
    looking = threading.Event()
    go = threading.Event()
    real_look = pacing._look

    def slow_look(path):
        result = real_look(path)
        if path.name.endswith(".1.lock") and not looking.is_set():
            looking.set()  # A has slot 1 locked just now
            assert go.wait(timeout=10)
        return result

    monkeypatch.setattr(pacing, "_look", slow_look)
    results: dict[str, pacing.Slot] = {}

    def run(name: str) -> None:
        results[name] = pacing.acquire(tmp_path, URL, settings, 5.0)

    thread_a = threading.Thread(target=run, args=("a",))
    thread_a.start()
    assert looking.wait(timeout=10)
    thread_b = threading.Thread(target=run, args=("b",))
    thread_b.start()
    thread_b.join(timeout=0.3)
    assert thread_b.is_alive(), "B waits for the origin lock while A looks"
    go.set()
    thread_a.join(timeout=10)
    thread_b.join(timeout=10)

    assert results["a"].paced is None
    assert results["b"].paced is None, "B was not told the origin was busy"
    results["a"].release()
    results["b"].release()


def test_a_dead_start_note_in_another_slot_is_replaced_by_its_end_so_it_counts_once(tmp_path):
    clock = Time()
    settings = Pacing(runs_per_origin=2, min_interval_seconds=10)
    first = take(tmp_path, clock, pacing_=settings)
    second = take(tmp_path, clock, pacing_=settings)
    first.release()  # slot 0: an end time
    # Slot 1 is left with its note and let go, as a killed run leaves it (the kernel drops the
    # lock; the note stays).
    os.close(second._descriptor)
    second._descriptor = None
    note = (tmp_path / ".pacing").glob("*.1.lock")
    (slot_one,) = note
    assert slot_one.read_text().startswith(pacing.START_NOTE)
    clock.now += 100  # long past every interval

    with take(tmp_path, clock, pacing_=settings) as third:  # slot 0; slot 1 holds the dead note
        assert third.paced is not None and third.paced.why == "interval"
    assert float(slot_one.read_text()) == pytest.approx(1_000_100.0), "its end, as found"
    clock.now += 100
    with take(tmp_path, clock, pacing_=settings) as fourth:
        assert fourth.paced is None, "the note was counted once, not at every later run"


# -- runs through the command line -------------------------------------------------------------


@pytest.fixture(autouse=True)
def salt(monkeypatch):
    """The second version's file names ``salt_env: KYMOGRAPH_SALT``, and the gate refuses a run
    without a salt."""
    monkeypatch.setenv("KYMOGRAPH_SALT", "salt-" + secrets.token_hex(16))


@pytest.fixture
def clock(monkeypatch):
    """The wall clock and the sleeping of the module, one that moves itself on when slept."""
    fake = Time(start=time.time())
    monkeypatch.setattr(pacing, "_wall", fake)
    monkeypatch.setattr(pacing, "_sleep", fake.sleep)
    return fake


def run_directories(out_dir: Path) -> list[Path]:
    return sorted(path for path in out_dir.iterdir() if path.is_dir() and path.name != ".pacing")


def started_and_next(path: Path) -> tuple[dict, dict]:
    events = events_of(path / "events.jsonl")
    assert events[0]["type"] == "run_started"
    return events[0], events[1]


def drive_localhost(tmp_path, port, *extra, out="runs", engagement=None):
    args = [
        "drive",
        "-q",
        "--http",
        f"https://localhost:{port}/mcp",
        "--out-dir",
        str(tmp_path / out),
    ]
    if engagement is not None:
        args += ["--engagement", str(engagement)]
    return cli.main([*args, *extra])


def engaged(tmp_path, port, **changes):
    return write_engagement(
        tmp_path / "engagement",
        targets=[{"host": "localhost", "ports": [port], "paths": ["/mcp"]}],
        scenarios=None,
        **changes,
    )


def test_a_loopback_run_is_not_paced_and_says_so(tmp_path, serve):
    port = serve()
    out = tmp_path / "runs"
    for _ in range(2):
        code = cli.main(
            ["drive", "-q", "--http", f"http://127.0.0.1:{port}/mcp", "--out-dir", str(out)]
        )
        assert code == 0
    assert not (out / ".pacing").exists()
    for path in run_directories(out):
        started, following = started_and_next(path)
        assert started["pacing"] is None and started["pacing_enforced"] is None
        assert following["type"] != "paced"


def test_a_run_to_a_name_is_paced_by_the_defaults_without_a_file(tmp_path, trust_ca, serve, clock):
    port = serve(tls=TRUSTED)

    assert drive_localhost(tmp_path, port) == 0

    (path,) = run_directories(tmp_path / "runs")
    started, following = started_and_next(path)
    assert started["pacing_enforced"] is True
    assert started["pacing"] == {
        "runs_per_origin": 1,
        "min_interval_seconds": 10,
        "source": "default",
    }
    assert following["type"] != "paced", "the first run to an origin waits for nothing"
    slots = slot_files(tmp_path / "runs")
    assert len(slots) == 1 and stat.S_IMODE(slots[0].stat().st_mode) == 0o600


def test_the_second_run_waits_and_records_paced_right_after_run_started(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    assert drive_localhost(tmp_path, port) == 0
    clock.now += 2

    assert drive_localhost(tmp_path, port) == 0

    waited = [
        p for p in run_directories(tmp_path / "runs") if started_and_next(p)[1]["type"] == "paced"
    ]
    (path,) = waited
    started, paced = started_and_next(path)
    assert paced["why"] == "interval"
    assert paced["seconds"] >= 10 - 2 - 0.5, "the interval, less the time that passed and the slack"
    assert started["pacing_enforced"] is True
    assert clock.slept and clock.slept[-1] >= 7.5


def test_a_run_that_waited_for_a_busy_origin_records_paced_right_after_run_started(
    tmp_path, trust_ca, serve, clock, monkeypatch
):
    port = serve(tls=TRUSTED)
    held = engaged(tmp_path, port, pacing={"runs_per_origin": 1, "min_interval_seconds": 0})
    other = Time(start=clock.now)
    holder = take(
        tmp_path / "runs",
        other,
        url=f"https://localhost:{port}/mcp",
        pacing_=Pacing(1, 0),
    )

    def sleep(seconds):
        clock.sleep(seconds)
        holder.release()  # the other run ends while this one polls

    monkeypatch.setattr(pacing, "_sleep", sleep)

    assert drive_localhost(tmp_path, port, engagement=held) == 0

    (path,) = run_directories(tmp_path / "runs")
    started, paced = started_and_next(path)
    assert paced["type"] == "paced" and paced["why"] == "origin_busy"
    assert paced["seconds"] > 0
    assert started["pacing_enforced"] is True


def test_the_file_sets_the_values_and_names_itself_as_the_source(tmp_path, trust_ca, serve, clock):
    port = serve(tls=TRUSTED)
    held = engaged(tmp_path, port, pacing={"runs_per_origin": 2, "min_interval_seconds": 0})

    assert drive_localhost(tmp_path, port, engagement=held) == 0

    (path,) = run_directories(tmp_path / "runs")
    started, _ = started_and_next(path)
    assert started["pacing"] == {
        "runs_per_origin": 2,
        "min_interval_seconds": 0,
        "source": "file",
    }


def test_a_wait_over_the_step_timeout_is_refused_with_no_run_directory_and_one_line(
    tmp_path, trust_ca, serve, clock, capsys
):
    port = serve(tls=TRUSTED)
    held = engaged(tmp_path, port)
    assert drive_localhost(tmp_path, port, engagement=held) == 0
    (first,) = run_directories(tmp_path / "runs")
    capsys.readouterr()

    code = drive_localhost(tmp_path, port, "--step-timeout", "5", engagement=held)

    assert code == 2
    assert run_directories(tmp_path / "runs") == [first], "no run directory is made"
    assert "--step-timeout" in capsys.readouterr().err
    refused = refusals_in(tmp_path / "runs")
    assert [r.reason for r in refused] == ["pacing"]
    assert clock.slept == [], "nothing was waited for"


@pytest.mark.parametrize(
    ("hold", "said"),
    [("slot", "in use"), ("lock", "locked by another process")],
)
def test_an_origin_that_stays_busy_refuses_the_run_on_the_command_line_with_its_host_masked(
    tmp_path, trust_ca, serve, clock, capfd, hold, said
):
    """Through ``cli.main``: reason ``pacing``, exit 2, no run directory, one line, and a known
    value in the host neither on the terminal nor in the file."""
    port = serve(tls=TRUSTED)
    url = f"https://localhost:{port}/mcp"
    data = probing(
        targets=[{"host": "localhost", "ports": [port], "paths": ["/mcp"]}],
        known_values=["localhost"],
    )
    (tmp_path / "engagement").mkdir(exist_ok=True)
    file = write(tmp_path / "engagement", data)
    out = tmp_path / "runs"
    slot = pacing.acquire(out, url, Pacing(1, 0), 5.0)
    holder = None
    if hold == "lock":
        slot.release()
        digest = hashlib.sha256(pacing.origin_of(url).encode()).hexdigest()
        holder = os.open(out / ".pacing" / f"{digest}.lock", os.O_RDWR)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        code = drive_localhost(tmp_path, port, "--step-timeout", "2", engagement=file)
    finally:
        if holder is None:
            slot.release()
        else:
            os.close(holder)

    assert code == 2
    assert run_directories(out) == [], "no run directory is made"
    assert [r.reason for r in refusals_in(out)] == ["pacing"]
    err = capfd.readouterr().err
    written = (out / engagement.REFUSALS_FILE).read_text()
    for text in (err, written):
        assert said in text
        assert "***KNOWN-" in text
        assert "localhost" not in text


def test_a_refusal_without_a_file_exits_2_and_is_said(tmp_path, trust_ca, serve, clock, capsys):
    port = serve(tls=TRUSTED)
    assert drive_localhost(tmp_path, port) == 0
    capsys.readouterr()

    assert drive_localhost(tmp_path, port, "--step-timeout", "5") == 2

    assert "min_interval_seconds" in capsys.readouterr().err
    assert len(run_directories(tmp_path / "runs")) == 1


def test_two_identities_on_one_origin_share_the_slots_and_the_second_is_paced(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    identities = [
        {"name": "reader", "role": "read-only user", "token": "none"},
        {"name": "admin", "role": "administrator", "token": "none"},
    ]
    held = engaged(tmp_path, port, identities=identities)

    assert drive_localhost(tmp_path, port, "--identity", "reader", engagement=held) == 0
    assert drive_localhost(tmp_path, port, "--identity", "admin", engagement=held) == 0

    by_identity = {}
    for path in run_directories(tmp_path / "runs"):
        started, following = started_and_next(path)
        by_identity[started["auth"]["identity"]] = following
    assert by_identity["reader"]["type"] != "paced"
    assert by_identity["admin"]["type"] == "paced"
    assert by_identity["admin"]["why"] == "interval"
    assert len(slot_files(tmp_path / "runs")) == 1, "one origin, one slot"


def test_a_slot_is_let_go_when_the_run_ends_so_the_next_one_does_not_find_it_busy(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    held = engaged(tmp_path, port, pacing={"runs_per_origin": 1, "min_interval_seconds": 0})
    assert drive_localhost(tmp_path, port, engagement=held) == 0
    assert drive_localhost(tmp_path, port, engagement=held) == 0
    for path in run_directories(tmp_path / "runs"):
        assert started_and_next(path)[1]["type"] != "paced"


def test_a_destination_that_is_refused_is_refused_by_the_destination_not_by_pacing(
    tmp_path, trust_ca, serve, clock, capsys
):
    port = serve(tls=TRUSTED)
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory")

    code = cli.main(
        ["drive", "-q", "--http", f"https://localhost:{port}/mcp", "--out-dir", str(blocker / "x")]
    )

    assert code == 2
    assert not os.path.isdir(blocker / "x")
    assert "output directory" in capsys.readouterr().err


def test_a_slot_that_cannot_be_taken_is_a_refusal_with_one_line_and_no_path(
    tmp_path, trust_ca, capsys, monkeypatch
):
    server = http_server.serve(0, "127.0.0.1", tls=TRUSTED)
    try:
        port = server.server_address[1]
        out = tmp_path / "runs"

        def broken(*_args, **_kwargs):
            raise PermissionError(13, "Permission denied", str(out / ".pacing"))

        monkeypatch.setattr(pacing, "acquire", broken)

        code = cli.main(
            ["drive", "-q", "--http", f"https://localhost:{port}/mcp", "--out-dir", str(out)]
        )

        err = capsys.readouterr().err
        assert code == 2
        assert "Permission denied" in err and len(err.strip().splitlines()) == 1
        assert str(out) not in err and str(tmp_path) not in err, "no path, ever"
        assert server.behaviour.heads == [], "nothing connected"
        assert not out.exists() or run_directories(out) == [], "no run directory"
    finally:
        server.shutdown()
        server.server_close()


def test_a_pacing_directory_that_was_there_with_a_wider_mode_is_0700_after_the_run(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED)
    directory = tmp_path / "runs" / ".pacing"
    directory.mkdir(parents=True, mode=0o755)
    directory.chmod(0o755)

    assert drive_localhost(tmp_path, port) == 0

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_a_pacing_directory_that_is_a_link_is_refused_and_its_target_is_left_alone(
    tmp_path, trust_ca, serve, clock, capsys
):
    port = serve(tls=TRUSTED)
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / ".pacing").symlink_to(target, target_is_directory=True)

    code = drive_localhost(tmp_path, port)

    err = capsys.readouterr().err
    assert code == 2
    assert stat.S_IMODE(target.stat().st_mode) == 0o755, "the target was not changed"
    assert list(target.iterdir()) == [], "nothing was made in it"
    assert str(tmp_path) not in err, "no path, ever"
    assert run_directories(tmp_path / "runs") == [], "no run directory"


def git_checkout(path: Path, ignored: str) -> Path:
    git = shutil.which("git")
    assert git, "these tests need a git binary"
    path.mkdir()
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=path, check=True)  # noqa: S603
    (path / ".gitignore").write_text(f"{ignored}\n")
    return path


def test_a_paced_run_whose_pacing_directory_is_refused_is_refused_before_it_connects(
    tmp_path, trust_ca, capsys
):
    """The ignore rules cover the run directory (``runs/2…``) and not ``runs/.pacing``: the
    destination check of the one passes and of the other does not. The run is not made without a
    slot."""
    server = http_server.serve(0, "127.0.0.1", tls=TRUSTED)
    try:
        port = server.server_address[1]
        repo = git_checkout(tmp_path / "repo", "/runs/2*")
        out = repo / "runs"

        code = cli.main(
            ["drive", "-q", "--http", f"https://localhost:{port}/mcp", "--out-dir", str(out)]
        )

        err = capsys.readouterr().err
        assert code == 2
        assert "not covered by the ignore rules" in err
        assert "the pacing directory .pacing in the output directory" in err
        assert str(out) not in err and str(tmp_path) not in err, "no path, ever"
        assert server.behaviour.heads == [], "nothing connected"
        assert not out.exists() or list(out.iterdir()) == [], "no run directory, no slot"
    finally:
        server.shutdown()
        server.server_close()


# -- an active probe -------------------------------------------------------------------------


def probing_file(tmp_path, port):
    """A file of the second version that lists the module ``echo`` and the one tool the fixture
    server serves, for the host ``localhost`` on the server's port."""
    data = probing(
        targets=[{"host": "localhost", "ports": [port], "paths": ["/mcp"]}],
        tools=[{"name": "tool_0", "writes": False}],
    )
    (tmp_path / "engagement").mkdir(exist_ok=True)
    return write(tmp_path / "engagement", data)


def test_a_run_of_a_probe_takes_the_slot_and_the_interval_like_any_http_run(
    tmp_path, trust_ca, serve, clock
):
    port = serve(tls=TRUSTED, call_result="text")
    held = probing_file(tmp_path, port)
    probe = ["--probe", "echo", "--probe-option", "tool=tool_0"]

    assert drive_localhost(tmp_path, port, *probe, engagement=held) == 0
    assert drive_localhost(tmp_path, port, *probe, engagement=held) == 0

    second = []
    for path in run_directories(tmp_path / "runs"):
        events = events_of(path / "events.jsonl")
        assert events[0]["probe"]["name"] == "echo"
        assert events[0]["pacing_enforced"] is True
        assert [e["type"] for e in events].count("step_called") == 1, "the probe did call"
        if events[1]["type"] == "paced":
            second.append(events[1])
    (paced,) = second
    assert paced["why"] == "interval"
    assert paced["seconds"] >= 10 - 0.5


def test_the_notice_of_a_wait_holds_no_known_value_of_the_host(
    tmp_path, trust_ca, serve, clock, capfd
):
    """The host goes through the masker before it reaches the terminal, as it does in the
    recording and in a refusal."""
    port = serve(tls=TRUSTED, call_result="text")
    data = probing(
        targets=[{"host": "localhost", "ports": [port], "paths": ["/mcp"]}],
        tools=[{"name": "tool_0", "writes": False}],
        known_values=["localhost"],
    )
    (tmp_path / "engagement").mkdir(exist_ok=True)
    held = write(tmp_path / "engagement", data)
    probe = ["--probe", "echo", "--probe-option", "tool=tool_0"]

    assert drive_localhost(tmp_path, port, *probe, engagement=held) == 0
    capfd.readouterr()
    assert drive_localhost(tmp_path, port, *probe, engagement=held) == 0

    (notice,) = [
        line for line in capfd.readouterr().err.splitlines() if line.count("paced: waited")
    ]
    assert "(interval) for https://***KNOWN-" in notice
    assert "localhost" not in notice


# -- 429 and 503 ---------------------------------------------------------------------------------


@pytest.fixture
def limited():
    """``http_limits.serve``: the port of a TLS fixture server that answers ``limits`` first."""
    import http_limits

    servers = []

    def started(limits, **options):
        server = http_limits.serve(limits, tls=TRUSTED, **options)
        servers.append(server)
        return server.server_address[1]

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def waits(monkeypatch):
    """The driver's wait for a ``Retry-After``, which records the seconds instead of sleeping."""
    from mcp_kymograph import driver

    slept = []

    async def sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(driver, "_sleep", sleep)
    return slept


def last_run(tmp_path) -> list[dict]:
    (path,) = run_directories(tmp_path / "runs")
    return events_of(path / "events.jsonl")


def of(events, kind):
    return [e for e in events if e["type"] == kind]


def retry(status, after="1", method="tools/list"):
    headers = {} if after is None else {"Retry-After": after}
    return (method, status, headers)


@pytest.mark.parametrize("status", [429, 503])
def test_a_retry_after_in_seconds_is_waited_for_once_and_the_step_then_succeeds(
    tmp_path, trust_ca, limited, clock, waits, status
):
    port = limited([retry(status)])

    assert drive_localhost(tmp_path, port) == 0

    events = last_run(tmp_path)
    assert waits == [1]
    (paced,) = of(events, "paced")
    assert (paced["why"], paced["status"]) == ("retry_after", status)
    assert paced["seconds"] >= 1
    assert of(events, "step_unanswered") == [] and of(events, "server_failed") == []
    assert events[1]["type"] != "paced", "the run itself waited for nothing before it began"


def test_a_second_429_is_rate_limited_and_not_waited_for(tmp_path, trust_ca, limited, clock, waits):
    port = limited([retry(429), retry(429)])

    assert drive_localhost(tmp_path, port) != 0

    events = last_run(tmp_path)
    assert waits == [1], "one wait, not two"
    assert len(of(events, "paced")) == 1
    (unanswered,) = of(events, "step_unanswered")
    assert (unanswered["step"], unanswered["reason"]) == ("tools/list", "rate_limited")


def test_a_429_on_the_first_exchange_is_server_failed_rate_limited(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429, after=None, method=None)])

    assert drive_localhost(tmp_path, port) != 0

    (failed,) = of(last_run(tmp_path), "server_failed")
    assert failed["reason"] == "rate_limited"
    assert waits == []


def test_a_429_without_retry_after_is_rate_limited_at_once(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429, after=None)])

    assert drive_localhost(tmp_path, port) != 0

    events = last_run(tmp_path)
    assert waits == [] and of(events, "paced") == [], "no wait is invented"
    (unanswered,) = of(events, "step_unanswered")
    assert unanswered["reason"] == "rate_limited"


def test_a_503_without_retry_after_stays_http_status(tmp_path, trust_ca, limited, clock, waits):
    port = limited([retry(503, after=None)])

    assert drive_localhost(tmp_path, port) != 0

    (unanswered,) = of(last_run(tmp_path), "step_unanswered")
    assert unanswered["reason"] == "http_status"
    assert waits == []


@pytest.mark.parametrize(
    ("status", "reason"), [(429, "rate_limited"), (503, "http_status")], ids=["429", "503"]
)
def test_a_retry_after_as_an_http_date_is_not_waited_for(
    tmp_path, trust_ca, limited, clock, waits, status, reason
):
    port = limited([retry(status, after="Wed, 21 Oct 2037 07:28:00 GMT")])

    assert drive_localhost(tmp_path, port) != 0

    (unanswered,) = of(last_run(tmp_path), "step_unanswered")
    assert unanswered["reason"] == reason, "handled as if the header were not there"
    assert waits == []


def test_a_retry_after_over_what_the_step_has_left_is_rate_limited_without_waiting(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429, after="60")])

    assert drive_localhost(tmp_path, port, "--step-timeout", "30") != 0

    (unanswered,) = of(last_run(tmp_path), "step_unanswered")
    assert unanswered["reason"] == "rate_limited"
    assert waits == []


def test_the_wait_of_a_retry_after_is_the_same_inside_a_probe(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429, method="tools/call")], call_result="text")
    held = probing_file(tmp_path, port)
    probe = ["--probe", "echo", "--probe-option", "tool=tool_0"]

    assert drive_localhost(tmp_path, port, *probe, engagement=held) == 0

    events = last_run(tmp_path)
    assert waits == [1]
    (paced,) = of(events, "paced")
    assert (paced["why"], paced["status"]) == ("retry_after", 429)
    assert [e["type"] for e in events].count("step_called") == 1, "the call is counted once"


def test_the_refusal_of_the_pacing_directory_names_it_and_no_path_on_the_terminal_or_in_the_file(
    tmp_path, trust_ca, capsys
):
    server = http_server.serve(0, "127.0.0.1", tls=TRUSTED)
    try:
        port = server.server_address[1]
        repo = git_checkout(tmp_path / "repo", "/runs/2*\n/runs/refusals.jsonl")
        out = repo / "runs"
        held = engaged(tmp_path, port)

        code = cli.main(
            [
                *("drive", "-q", "--http", f"https://localhost:{port}/mcp"),
                *("--out-dir", str(out), "--engagement", str(held)),
            ]
        )

        err = capsys.readouterr().err
        (record,) = refusals_in(out)
        assert code == 2 and record.reason == "destination"
        for text in (err, record.message):  # the command line in the file is the operator's own
            assert ".pacing" in text
            assert "--out-dir" not in text and str(tmp_path) not in text
    finally:
        server.shutdown()
        server.server_close()


# -- after the wait: the run may be over, and any 429 or 503 is the limit again ----------------


@pytest.fixture
def counted(tmp_path):
    """Like ``limited``, and ``posts`` lists the method of every POST the server received."""
    import http_limits

    servers = []
    posts: list[str | None] = []

    def started(limits, **options):
        server = http_limits.serve(limits, tls=TRUSTED, **options)
        servers.append(server)
        handler = server.RequestHandlerClass

        class Counting(handler):
            def do_POST(self):  # noqa: N802 - the name http.server calls
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                posts.append(json.loads(body).get("method"))
                self.rfile = io.BytesIO(body)  # the handler reads the body itself
                super().do_POST()

        server.RequestHandlerClass = Counting
        return server.server_address[1]

    started.posts = posts
    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


def sleeping_through(monkeypatch, then):
    """The driver's wait for a ``Retry-After``, which runs ``then`` instead of sleeping."""
    from mcp_kymograph import driver

    async def sleep(seconds):
        then()

    monkeypatch.setattr(driver, "_sleep", sleep)


def test_a_window_that_ends_during_the_wait_sends_nothing_and_ends_with_the_window(
    tmp_path, trust_ca, counted, clock, monkeypatch
):
    port = counted([retry(429)])
    held = engaged(tmp_path, port)
    shift = [timedelta(0)]

    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return super().now(tz) + shift[0]

    monkeypatch.setattr(proxy, "datetime", Later)
    sleeping_through(monkeypatch, lambda: shift.__setitem__(0, timedelta(days=2)))

    assert drive_localhost(tmp_path, port, engagement=held) != 0

    events = last_run(tmp_path)
    assert counted.posts.count("tools/list") == 1, "the request was not sent again"
    (paced,) = of(events, "paced")
    assert paced["why"] == "retry_after"
    assert not of(events, "step_unanswered"), "a halt after the wait is a halt before the step"
    assert ("tools/list", "run_halted") in [
        (e["step"], e["reason"]) for e in of(events, "step_skipped")
    ]
    (finished,) = of(events, "run_finished")
    assert finished["reason"] == "window_closed" and finished["window_exceeded"] is True


def test_a_stop_file_that_appears_during_the_wait_sends_nothing_and_ends_with_the_stop(
    tmp_path, trust_ca, counted, clock, monkeypatch
):
    port = counted([retry(429)])
    held = engaged(tmp_path, port)
    sleeping_through(monkeypatch, lambda: engagement.stop_path(held).write_text("stop\n"))

    assert drive_localhost(tmp_path, port, engagement=held) != 0

    events = last_run(tmp_path)
    assert counted.posts.count("tools/list") == 1, "the request was not sent again"
    assert len(of(events, "paced")) == 1
    assert not of(events, "step_unanswered"), "a halt after the wait is a halt before the step"
    assert ("tools/list", "run_halted") in [
        (e["step"], e["reason"]) for e in of(events, "step_skipped")
    ]
    (finished,) = of(events, "run_finished")
    assert finished["reason"] == "stop_file"


@pytest.mark.parametrize(
    "limits",
    [
        [retry(503), retry(503, after=None)],
        [retry(429), retry(503, after=None)],
        [retry(503), retry(429, after=None)],
    ],
    ids=["503-503", "429-503", "503-429"],
)
def test_a_429_or_503_after_the_wait_is_rate_limited_with_or_without_the_header(
    tmp_path, trust_ca, limited, clock, waits, limits
):
    port = limited(limits)

    assert drive_localhost(tmp_path, port) != 0

    events = last_run(tmp_path)
    assert waits == [1], "one wait, not two"
    (unanswered,) = of(events, "step_unanswered")
    assert (unanswered["step"], unanswered["reason"]) == ("tools/list", "rate_limited")


def test_runs_per_origin_is_taken_up_to_64_and_refused_above(tmp_path):
    for runs, accepted in ((64, True), (65, False)):
        data = probing(pacing={"runs_per_origin": runs})
        directory = tmp_path / str(runs)
        directory.mkdir()
        path = write(directory, data)
        if accepted:
            engagement.load(path)
        else:
            with pytest.raises(engagement.EngagementError) as raised:
                engagement.load(path)
            assert "pacing.runs_per_origin" in str(raised.value) and "64" in str(raised.value)


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="needs /proc/self/fd")
def test_the_slots_are_opened_one_at_a_time_and_few_descriptors_stay_open(tmp_path, monkeypatch):
    time_ = Time()
    settings = Pacing(runs_per_origin=64, min_interval_seconds=0)
    held = [take(tmp_path, time_, pacing_=settings) for _ in range(63)]
    before = len(os.listdir("/proc/self/fd"))
    peak = [0]
    looking = pacing._look

    def counting(path):
        looked = looking(path)
        peak[0] = max(peak[0], len(os.listdir("/proc/self/fd")) - before)
        return looked

    monkeypatch.setattr(pacing, "_look", counting)
    try:
        last = take(tmp_path, time_, pacing_=settings)
        files = (tmp_path / ".pacing").glob("*.lock")
        assert len(list(files)) == 64 + 1, "all 64 slots and the origin's lock were made"
        last.release()
    finally:
        for slot in held:
            slot.release()
    assert peak[0] <= 2, f"{peak[0]} descriptors were open besides the ones held before"


def test_an_endpoint_entry_is_paced_like_drive_http_and_its_second_run_waits(
    tmp_path, trust_ca, serve, clock
):
    from test_cli_endpoint import endpoint_manifest

    port = serve(tls=TRUSTED)
    manifest = endpoint_manifest(tmp_path / "manifest", f"https://localhost:{port}/mcp")
    out = tmp_path / "runs"
    argv = ["drive", "-q", "--manifest", str(manifest), "--entry", "customer-mcp"]
    argv += ["--engagement-confirmed"]  # the entry's scenario names a host that is not local

    assert cli.main([*argv, "--out-dir", str(out)]) == 0
    clock.now += 2
    assert cli.main([*argv, "--out-dir", str(out)]) == 0

    runs = [events_of(p / "events.jsonl") for p in run_directories(out)]
    assert len(runs) == 2
    for events in runs:
        assert events[0]["pacing_enforced"] is True
        assert events[0]["pacing"]["runs_per_origin"] == 1
    waited = [events for events in runs if events[1]["type"] == "paced"]
    assert len(waited) == 1 and waited[0][1]["why"] == "interval"


# -- a halt after the wait is written as a halt before the step ----------------------------------


@pytest.fixture
def hooked():
    """Like ``limited``, and ``hooks`` maps a method to what runs when the server receives it,
    before it answers. ``paged`` makes the first page of ``tools/list`` point on to a second."""
    import http_limits

    servers = []

    def started(limits, *, paged=False, **options):
        server = http_limits.serve(limits, tls=TRUSTED, **options)
        servers.append(server)
        handler = server.RequestHandlerClass
        hooks: dict = {}

        class Hooked(handler):
            def do_POST(self):  # noqa: N802 - the name http.server calls
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                request = json.loads(body)
                method = request.get("method")
                if method in hooks:
                    hooks[method]()
                params = request.get("params") or {}
                if paged and method == "tools/list" and "cursor" not in params:
                    if self._in_session():
                        tool = {"name": "tool_0", "inputSchema": {"type": "object"}}
                        result = {"tools": [tool], "nextCursor": "page-1"}
                        self._json(200, {"jsonrpc": "2.0", "id": request["id"], "result": result})
                    return
                self.rfile = io.BytesIO(body)  # the handler reads the body itself
                super().do_POST()

        server.RequestHandlerClass = Hooked
        started.hooks, started.limits = hooks, server.limits
        return server.server_address[1]

    yield started
    for server in servers:
        server.shutdown()
        server.server_close()


class Halt:
    """A way to stop a run: after ``arm()`` the question "may the run go on" says no."""

    def __init__(self, kind, monkeypatch, held):
        self.kind, self.held = kind, held
        self.shift = [timedelta(0)]
        shift = self.shift

        class Later(datetime):
            @classmethod
            def now(cls, tz=None):
                return super().now(tz) + shift[0]

        monkeypatch.setattr(proxy, "datetime", Later)

    def arm(self):
        if self.kind == "stop_file":
            engagement.stop_path(self.held).write_text("stop\n")
        else:
            self.shift[0] = timedelta(days=2)

    def clear(self):
        engagement.stop_path(self.held).unlink(missing_ok=True)
        self.shift[0] = timedelta(0)


def recorded(tmp_path, out):
    """``(events, verdict)`` of the one run under ``out``."""
    (path,) = run_directories(tmp_path / out)
    return events_of(path / "events.jsonl"), verdict.read(path / "events.jsonl")


def the_steps(events):
    """The steps that were not sent or not answered in full, and the script's end without what it
    lists as sent and called: the run that waited sent its first attempt, the other did not."""
    kept = ("step_skipped", "step_unanswered", "script_finished")
    return [
        {
            key: value
            for key, value in e.items()
            if key not in ("run_id", "seq", "t_ns", "sent", "called")
        }
        for e in events
        if e["type"] in kept
    ]


def halted_twice(tmp_path, hooked, monkeypatch, kind, *, limit, trigger=None, probe=False):
    """Two runs against one server, each in an out-directory of its own. The first is stopped
    before the step: the halt is armed when the server receives ``trigger`` (None: before the
    run). The second gets ``limit``, a 429 with a ``Retry-After``, and the halt comes in the
    wait. Returns the exit status of each and its ``(events, verdict)``."""
    port = hooked([], call_result="text")
    held = probing_file(tmp_path, port) if probe else engaged(tmp_path, port)
    halt = Halt(kind, monkeypatch, held)
    extra = ["--probe", "echo", "--probe-option", "tool=tool_0"] if probe else []
    from mcp_kymograph import driver

    converse = driver.Driver._converse
    if trigger is None:

        async def armed(self):  # the run is on its way, and nothing was sent yet
            halt.arm()
            await converse(self)

        monkeypatch.setattr(driver.Driver, "_converse", armed)
    else:
        hooked.hooks[trigger] = halt.arm
    before = drive_localhost(tmp_path, port, *extra, out="before", engagement=held)
    halt.clear()
    hooked.hooks.clear()
    if trigger is None:
        monkeypatch.setattr(driver.Driver, "_converse", converse)
    hooked.limits.append(limit)
    sleeping_through(monkeypatch, halt.arm)
    after = drive_localhost(tmp_path, port, *extra, out="after", engagement=held)
    return (before, after), [recorded(tmp_path, out) for out in ("before", "after")]


def assert_same_ending(codes, runs):
    """The two runs ended the same way: exit status, verdict, the steps' events. The second adds
    only the events of its first attempt and the ``paced``."""
    (events_a, verdict_a), (events_b, verdict_b) = runs
    assert codes[0] == codes[1] != 0
    assert (verdict_b.state, verdict_b.causes) == (verdict_a.state, verdict_a.causes)
    assert verdict_b.exit_code == verdict_a.exit_code
    assert the_steps(events_b) == the_steps(events_a)
    assert not of(events_b, "step_unanswered")
    assert len(of(events_b, "paced")) == 1 and not of(events_a, "paced")


def skipped_in(events):
    return [(e["step"], e["reason"]) for e in of(events, "step_skipped")]


@pytest.mark.parametrize("kind", ["stop_file", "window"])
def test_a_halt_in_the_wait_before_tools_list_is_the_halt_before_that_step(
    tmp_path, trust_ca, hooked, monkeypatch, waits, kind
):
    codes, runs = halted_twice(
        tmp_path, hooked, monkeypatch, kind, limit=retry(429), trigger="initialize"
    )

    assert_same_ending(codes, runs)
    skipped = skipped_in(runs[1][0])
    assert skipped[0] == ("tools/list", "run_halted") and len(skipped) > 1
    assert {reason for _, reason in skipped} == {"run_halted"}


@pytest.mark.parametrize("kind", ["stop_file", "window"])
def test_a_halt_in_the_wait_before_a_probes_tools_call_is_the_halt_before_that_request(
    tmp_path, trust_ca, hooked, monkeypatch, waits, kind
):
    codes, runs = halted_twice(
        tmp_path,
        hooked,
        monkeypatch,
        kind,
        limit=retry(429, method="tools/call"),
        trigger="tools/list",
        probe=True,
    )

    assert_same_ending(codes, runs)
    assert skipped_in(runs[1][0]) == [("tools/call", "run_halted")]


def test_a_halt_in_the_wait_before_a_probes_tools_list_is_the_halt_before_that_request(
    tmp_path, trust_ca, hooked, monkeypatch, waits
):
    codes, runs = halted_twice(
        tmp_path,
        hooked,
        monkeypatch,
        "stop_file",
        limit=retry(429),
        trigger="initialize",
        probe=True,
    )

    assert_same_ending(codes, runs)
    assert skipped_in(runs[1][0]) == [("tools/list", "run_halted")]


def test_a_halt_in_the_wait_before_the_second_page_leaves_a_listing_that_is_not_complete(
    tmp_path, trust_ca, hooked, monkeypatch, waits
):
    port = hooked([retry(429)], paged=True)
    held = engaged(tmp_path, port)
    halt = Halt("stop_file", monkeypatch, held)
    sleeping_through(monkeypatch, halt.arm)

    assert drive_localhost(tmp_path, port, engagement=held) != 0

    events, judged = recorded(tmp_path, "runs")
    (unanswered,) = of(events, "step_unanswered")
    assert (unanswered["step"], unanswered["pages"], unanswered["reason"]) == (
        "tools/list",
        1,
        "run_halted",
    )
    skipped = skipped_in(events)
    assert skipped and {reason for _, reason in skipped} == {"run_halted"}
    assert "tools/list" not in [step for step, _ in skipped], "the listing is said once"
    assert of(events, "script_finished")[0]["inventory"] != "complete"
    assert judged.state != "complete"


@pytest.mark.parametrize("method", [None, "initialize"], ids=["probe", "initialize"])
def test_a_halt_in_the_wait_of_the_opening_ends_it_without_the_era_detection(
    tmp_path, trust_ca, hooked, monkeypatch, waits, method
):
    codes, runs = halted_twice(
        tmp_path, hooked, monkeypatch, "stop_file", limit=retry(429, method=method)
    )

    assert_same_ending(codes, runs)
    events = runs[1][0]
    assert not {e["type"] for e in events} & {"era_decided", "server_failed"}
    text = json.dumps(events)
    assert "handshake_closed" not in text and "connection_closed" not in text
    skipped = skipped_in(events)
    assert skipped and {reason for _, reason in skipped} == {"run_halted"}


@pytest.mark.parametrize("kind", ["stop_file", "window"])
def test_a_halt_in_the_wait_of_the_opening_of_a_probes_run_skips_the_probe_step_once(
    tmp_path, trust_ca, hooked, monkeypatch, waits, kind
):
    codes, runs = halted_twice(
        tmp_path, hooked, monkeypatch, kind, limit=retry(429, method=None), probe=True
    )

    assert_same_ending(codes, runs)
    for events, judged in runs:
        assert skipped_in(events) == [("probe", "run_halted")]
        assert not of(events, "era_decided")
        assert (judged.state, judged.causes, judged.exit_code) == ("incomplete", ["interrupted"], 3)
    assert codes == (3, 3)


def test_a_pass_over_the_slots_that_raises_leaves_the_chosen_slot_as_it_was(tmp_path):
    time_ = Time()
    settings = Pacing(runs_per_origin=3, min_interval_seconds=10)
    take(tmp_path, time_, pacing_=settings).release()  # slot 0 now holds an end time
    (first,) = slot_files(tmp_path)[:1]
    time_.now += 1000
    before = first.read_bytes()
    third = first.with_name(first.name.replace(".0.", ".2."))
    third.unlink()
    third.symlink_to(tmp_path / "elsewhere")  # O_NOFOLLOW: ELOOP, after slot 0 was chosen

    with pytest.raises(OSError):
        take(tmp_path, time_, pacing_=settings)

    assert first.read_bytes() == before, "no start note was left in the slot"
    descriptor = os.open(first, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)  # the lock was let go
    finally:
        os.close(descriptor)
    third.unlink()
    take(tmp_path, time_, pacing_=settings)
    assert time_.slept == [], "a run that never happened is not waited for"


# -- runs with different runs_per_origin on one origin -------------------------------------------


def holding_two(tmp_path, time_, interval=10):
    """A run with 2 holds slot 0 and slot 1, taken in that order."""
    settings = Pacing(runs_per_origin=2, min_interval_seconds=interval)
    return take(tmp_path, time_, pacing_=settings), take(tmp_path, time_, pacing_=settings)


def test_a_run_with_fewer_slots_waits_for_a_slot_beyond_its_number_that_is_held(tmp_path):
    time_ = Time()
    first, second = holding_two(tmp_path, time_, interval=0)
    first.release()  # slot 0 is free, slot 1 is still held
    polls = []

    def let_go_after_three_polls(seconds: float) -> None:
        time_.sleep(seconds)
        polls.append(seconds)
        if len(polls) == 3:
            second.release()

    slot = bounded(
        lambda: pacing.acquire(
            tmp_path, URL, Pacing(1, 0), 30.0, clock=time_, sleep=let_go_after_three_polls
        )
    )
    with slot:
        assert slot.paced is not None and slot.paced.why == "origin_busy"
        assert len(polls) == 3, "it started when slot 1 was free, and not before"


def test_the_interval_is_measured_from_an_end_in_a_slot_beyond_the_runs_number(tmp_path):
    time_ = Time()
    first, second = holding_two(tmp_path, time_)
    first.release()  # an older end in slot 0
    time_.now += 5
    second.release()  # the latest end, in slot 1, at T

    with take(tmp_path, time_) as slot:
        assert slot.paced is not None and slot.paced.why == "interval"
    assert time_.slept == [pytest.approx(10.0)], "T + min_interval_seconds, not slot 0's end"


def test_a_dead_note_in_a_slot_beyond_the_runs_number_costs_the_full_interval_and_becomes_an_end(
    tmp_path,
):
    time_ = Time()
    first, second = holding_two(tmp_path, time_)
    first.release()
    os.close(second._descriptor)  # as a killed run leaves it: the note stays, the lock goes
    second._descriptor = None
    (slot_one,) = (tmp_path / ".pacing").glob("*.1.lock")
    assert slot_one.read_text().startswith(pacing.START_NOTE)
    time_.now += 100  # long past the end in slot 0

    with take(tmp_path, time_) as slot:
        assert slot.paced is not None and slot.paced.why == "interval"
    assert time_.slept == [pytest.approx(10.0)], "the full interval from where it was found"
    assert float(slot_one.read_text()) == pytest.approx(1_000_100.0), "the note is an end now"


def test_a_run_alone_makes_no_slot_beyond_its_number(tmp_path):
    time_ = Time()
    take(tmp_path, time_).release()
    take(tmp_path, time_).release()

    (only,) = slot_files(tmp_path)
    assert only.name.endswith(".0.lock")


def test_a_run_with_more_slots_takes_the_free_one_beyond_a_holder_with_fewer(tmp_path):
    time_ = Time()
    held = take(tmp_path, time_)  # a run with 1 holds slot 0

    with take(tmp_path, time_, pacing_=Pacing(2, 0)) as slot:
        assert slot.paced is None, "one held slot is fewer than 2"
        assert len(slot_files(tmp_path)) == 2
    held.release()


def test_a_run_counts_the_slots_held_by_runs_with_other_numbers_against_its_own(tmp_path):
    time_ = Time()
    three = take(tmp_path, time_, pacing_=Pacing(3, 0))  # slot 0
    two = take(tmp_path, time_, pacing_=Pacing(2, 0))  # slot 1
    more = take(tmp_path, time_, pacing_=Pacing(3, 0))  # slot 2
    three.release()  # slot 0 is free, slots 1 and 2 are held: the run with 2 has a free slot
    polls = []

    def let_go_after_three_polls(seconds: float) -> None:
        time_.sleep(seconds)
        polls.append(seconds)
        if len(polls) == 3:
            two.release()

    with pacing.acquire(
        tmp_path, URL, Pacing(2, 0), 30.0, clock=time_, sleep=let_go_after_three_polls
    ) as slot:
        assert slot.paced is not None and slot.paced.why == "origin_busy"
        assert len(polls) == 3, "two runs hold slots: as many as it allows, a free slot or not"
    more.release()


def test_a_busy_origin_leaves_the_slot_it_chose_byte_for_byte_as_it_was(tmp_path):
    time_ = Time()
    first, second = holding_two(tmp_path, time_)
    first.release()  # slot 0 is free and holds an end time; slot 1 is held
    time_.now += 100
    (slot_zero,) = tmp_path.glob(".pacing/*.0.lock")
    before = slot_zero.read_bytes()

    with pytest.raises(PacingRefused):  # one slot, a run holds slot 1: the pass finds it busy
        take(tmp_path, time_, pacing_=Pacing(1, 10), step_timeout=0.3)

    assert slot_zero.read_bytes() == before, "no start note in the slot it would have taken"
    second.release()


def test_the_message_of_a_busy_origin_says_no_count_of_other_runs_it_does_not_know(tmp_path):
    time_ = Time()
    holding = holding_two(tmp_path, time_)  # a run with 2 holds both of its slots

    with pytest.raises(PacingRefused) as refused:
        take(tmp_path, time_, pacing_=Pacing(1, 0), step_timeout=0.3)

    message = str(refused.value)
    assert "other run" not in message
    assert (
        "as many runs as runs_per_origin allows (1), or more, and did not free within "
        "--step-timeout (0.3 s); nothing was started"
    ) in message
    for slot in holding:
        slot.release()


def test_a_pass_that_raises_beyond_the_runs_number_leaves_the_chosen_slot_as_it_was(tmp_path):
    time_ = Time()
    take(tmp_path, time_).release()  # slot 0 now holds an end time
    (first,) = slot_files(tmp_path)
    time_.now += 1000
    before = first.read_bytes()
    beyond = first.with_name(first.name.replace(".0.", ".1."))
    beyond.symlink_to(tmp_path / "elsewhere")  # there, so it is read; O_NOFOLLOW: ELOOP

    with pytest.raises(OSError):
        take(tmp_path, time_)

    assert first.read_bytes() == before, "no start note was left in the slot"
    descriptor = os.open(first, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)  # the lock was let go
    finally:
        os.close(descriptor)


# -- the opening of a probe's run that fails, and tools/call as a step of a script ---------------


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize(
    ("cause", "causes"),
    [
        ("http_unreachable", ["http_unreachable"]),
        ("rate_limited", ["rate_limited", "server_silent"]),
    ],
)
def test_the_opening_of_a_probes_run_that_fails_for_another_reason_than_a_halt_skips_no_step(
    tmp_path, trust_ca, limited, clock, waits, cause, causes
):
    port = free_port() if cause == "http_unreachable" else limited([retry(429, None, None)])
    held = probing_file(tmp_path, port)

    code = drive_localhost(
        tmp_path, port, "--probe", "echo", "--probe-option", "tool=tool_0", engagement=held
    )

    events, judged = recorded(tmp_path, "runs")
    assert code == 4
    assert [e["reason"] for e in of(events, "server_failed")] == [cause]
    assert not of(events, "step_skipped"), "the probe's step stands in for a halt only"
    assert (judged.state, judged.causes, judged.exit_code) == ("server_failed", causes, 4)


CALLING = "\n".join(
    [
        "version: 1",
        "name: list-call-list",
        "steps:",
        "  - initialize",
        "  - list: tools/list",
        "  - call:",
        "      tool: tool_0",
        "  - list: resources/list",
        "",
    ]
)


def halted_twice_calling(tmp_path, hooked, monkeypatch, kind):
    """Two runs of the script ``CALLING``: the first is stopped by ``kind`` when the server
    receives ``tools/list``, the second gets a 429 with a ``Retry-After`` on ``tools/call`` and is
    stopped in the wait. Returns the exit status of each and its ``(events, verdict)``."""
    port = hooked([], call_result="text")
    held = probing_file(tmp_path, port)
    halt = Halt(kind, monkeypatch, held)
    script = tmp_path / "calling.yaml"
    script.write_text(CALLING)
    hooked.hooks["tools/list"] = halt.arm
    before = drive_localhost(tmp_path, port, "--script", str(script), out="before", engagement=held)
    halt.clear()
    hooked.hooks.clear()
    hooked.limits.append(retry(429, method="tools/call"))
    sleeping_through(monkeypatch, halt.arm)
    after = drive_localhost(tmp_path, port, "--script", str(script), out="after", engagement=held)
    return (before, after), [recorded(tmp_path, out) for out in ("before", "after")]


def compared_steps(events):
    """What ``engagement compare`` reads of a run: its steps, their answers, its lists."""
    return identity_compare._read_steps(events)


def test_a_comparison_reads_a_call_sent_again_after_a_retry_after_as_one_step(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429, method="tools/call")], call_result="text")
    held = probing_file(tmp_path, port)
    script = tmp_path / "calling.yaml"
    script.write_text(CALLING)

    assert drive_localhost(tmp_path, port, "--script", str(script), engagement=held) == 0

    events, _ = recorded(tmp_path, "runs")
    steps, answers, _ = compared_steps(events)
    assert [step.number for step in steps] == [1]
    assert (answers[1].outcome, answers[1].status) == ("ok", 200)


def test_a_comparison_reads_a_second_429_on_a_call_as_one_step_with_that_status(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited(
        [retry(429, method="tools/call"), retry(429, method="tools/call")], call_result="text"
    )
    held = probing_file(tmp_path, port)
    script = tmp_path / "calling.yaml"
    script.write_text(CALLING)

    drive_localhost(tmp_path, port, "--script", str(script), engagement=held)

    events, _ = recorded(tmp_path, "runs")
    steps, answers, _ = compared_steps(events)
    assert [step.number for step in steps] == [1]
    assert (answers[1].outcome, answers[1].status) == ("http_other", 429)


def test_a_comparison_reads_a_list_sent_again_after_a_retry_after_as_complete(
    tmp_path, trust_ca, limited, clock, waits
):
    port = limited([retry(429, method="tools/list")], call_result="text")
    held = probing_file(tmp_path, port)
    script = tmp_path / "calling.yaml"
    script.write_text(CALLING)

    assert drive_localhost(tmp_path, port, "--script", str(script), engagement=held) == 0

    events, _ = recorded(tmp_path, "runs")
    steps, _, lists = compared_steps(events)
    assert [step.number for step in steps] == [1], "a list is no step"
    assert lists["tools"].complete is True
    assert "tool_0" in lists["tools"].names


@pytest.mark.parametrize(
    "between", ["", "  - list: resources/list\n"], ids=["next", "after-a-list"]
)
def test_a_comparison_keeps_the_step_of_a_wait_that_left_no_time_and_the_next_steps_their_numbers(
    tmp_path, trust_ca, counted, clock, rolling, between
):
    """Nothing goes out again and the run is not halted: the step was sent and answered with the
    429, and what is skipped after it are the next steps, each with its number."""
    port = counted([retry(429, after="29", method="tools/call")], call_result="text")
    rolling.overshoot = 1.0
    held = probing_file(tmp_path, port)
    script = tmp_path / "three.yaml"
    script.write_text(
        "version: 1\nname: three\nsteps:\n  - initialize\n  - list: tools/list\n"
        "  - call:\n      tool: tool_0\n" + between + "  - call:\n      tool: tool_0\n"
        "  - call:\n      tool: tool_0\n"
    )

    arguments = ["--script", str(script), "--step-timeout", "30"]
    assert drive_localhost(tmp_path, port, *arguments, engagement=held) != 0

    events, _ = recorded(tmp_path, "runs")
    assert of(events, "paced") and of(events, "step_unanswered")
    steps, answers, _ = compared_steps(events)
    assert [step.number for step in steps] == [1, 2, 3]
    assert (answers[1].outcome, answers[1].status) == ("http_other", 429)
    assert [step.request for step in steps[1:]] == [None, None]


@pytest.mark.parametrize("kind", ["stop_file", "window"])
def test_a_comparison_reads_a_halt_in_the_wait_as_that_step_not_sent(
    tmp_path, trust_ca, hooked, monkeypatch, waits, kind
):
    _, runs = halted_twice_calling(tmp_path, hooked, monkeypatch, kind)
    events, _ = runs[1]

    steps, answers, _ = compared_steps(events)

    assert [(step.number, step.request) for step in steps] == [(1, None)]
    assert answers == {}


@pytest.mark.parametrize("kind", ["stop_file", "window"])
def test_a_halt_in_the_wait_before_a_scripts_tools_call_is_the_halt_before_that_step(
    tmp_path, trust_ca, hooked, monkeypatch, waits, kind
):
    codes, runs = halted_twice_calling(tmp_path, hooked, monkeypatch, kind)

    assert_same_ending(codes, runs)
    for events, _ in runs:
        assert skipped_in(events) == [
            ("tools/call", "run_halted"),
            ("resources/list", "run_halted"),
        ]
        assert len(of(events, "script_finished")) == 1


@pytest.fixture
def still_clock(monkeypatch):
    """The driver's monotonic clock held still, so that the time a step has left is exactly its
    timeout and no real second decides the comparison with ``Retry-After``."""
    from mcp_kymograph import driver

    monkeypatch.setattr(driver, "_monotonic", lambda: 1000.0)


def test_a_retry_after_equal_to_what_the_step_has_left_is_not_waited_for(
    tmp_path, trust_ca, limited, clock, waits, still_clock
):
    port = limited([retry(429, after="30")])

    assert drive_localhost(tmp_path, port, "--step-timeout", "30") != 0

    events = last_run(tmp_path)
    assert waits == [] and of(events, "paced") == []
    (unanswered,) = of(events, "step_unanswered")
    assert unanswered["reason"] == "rate_limited"


def test_a_retry_after_just_under_what_the_step_has_left_is_waited_for_and_sent_once_more(
    tmp_path, trust_ca, limited, clock, waits, still_clock
):
    port = limited([retry(429, after="29")])

    assert drive_localhost(tmp_path, port, "--step-timeout", "30") == 0

    events = last_run(tmp_path)
    assert waits == [29]
    (paced,) = of(events, "paced")
    assert (paced["why"], paced["status"]) == ("retry_after", 429)
    assert of(events, "step_unanswered") == []


@pytest.fixture
def rolling(monkeypatch):
    """The driver's monotonic clock and its wait as one: a sleep moves the clock on by the seconds
    asked and ``overshoot`` more, and nothing really waits. ``overshoot`` is set by the test."""
    from mcp_kymograph import driver

    state = types.SimpleNamespace(now=1000.0, overshoot=0.0, slept=[], then=lambda: None)

    async def sleep(seconds):
        state.slept.append(seconds)
        state.now += seconds + state.overshoot
        state.then()

    monkeypatch.setattr(driver, "_monotonic", lambda: state.now)
    monkeypatch.setattr(driver, "_sleep", sleep)
    return state


@pytest.mark.parametrize("overshoot", [1.0, 1.001], ids=["nothing-left", "just-under-nothing"])
def test_a_wait_that_leaves_no_time_sends_nothing_and_the_step_is_rate_limited(
    tmp_path, trust_ca, counted, clock, rolling, overshoot
):
    port = counted([retry(429, after="29")])
    rolling.overshoot = overshoot

    assert drive_localhost(tmp_path, port, "--step-timeout", "30") != 0

    events = last_run(tmp_path)
    assert rolling.slept == [29]
    assert counted.posts.count("tools/list") == 1, "the request was not sent again"
    (paced,) = of(events, "paced")
    assert (paced["why"], paced["status"]) == ("retry_after", 429)
    (unanswered,) = of(events, "step_unanswered")
    assert (unanswered["step"], unanswered["reason"]) == ("tools/list", "rate_limited")


def test_a_wait_that_leaves_a_little_time_sends_the_request_once_more(
    tmp_path, trust_ca, counted, clock, rolling
):
    port = counted([retry(429, after="29")])
    rolling.overshoot = 0.999  # 0.001 s of the step are left

    drive_localhost(tmp_path, port, "--step-timeout", "30")

    assert counted.posts.count("tools/list") == 2, "sent once more, as before"
    assert len(of(last_run(tmp_path), "paced")) == 1


def test_a_halt_in_a_wait_that_leaves_no_time_stays_the_halt(
    tmp_path, trust_ca, counted, clock, rolling
):
    port = counted([retry(429, after="29")])
    held = engaged(tmp_path, port)
    rolling.overshoot = 1.0
    rolling.then = lambda: engagement.stop_path(held).write_text("stop\n")

    assert drive_localhost(tmp_path, port, "--step-timeout", "30", engagement=held) != 0

    events = last_run(tmp_path)
    assert counted.posts.count("tools/list") == 1
    assert not of(events, "step_unanswered"), "the halt comes first"
    assert ("tools/list", "run_halted") in skipped_in(events)
    (finished,) = of(events, "run_finished")
    assert finished["reason"] == "stop_file"


# -- a slot that cannot be read or written, and an origin lock that is not let go ---------------


def open_descriptors() -> list[str]:
    return sorted(os.listdir("/proc/self/fd"))


def refuse_writes(monkeypatch, error=None, short=False, only_notes=True):
    """``os.pwrite`` that fails (or writes nothing and says 5), for the start note only."""
    real = os.pwrite

    def failing(descriptor, data, offset):
        if only_notes and not data.startswith(pacing.START_NOTE.encode()):
            return real(descriptor, data, offset)
        if short:
            return 5
        raise error or OSError(28, "No space left on device")

    monkeypatch.setattr(os, "pwrite", failing)


@pytest.mark.skipif(not Path("/proc/self/fd").is_dir(), reason="needs /proc/self/fd")
def test_a_slot_that_cannot_be_read_stops_the_run_and_leaves_no_descriptor_open(
    tmp_path, monkeypatch
):
    time_ = Time()
    take(tmp_path, time_).release()
    before = open_descriptors()

    def failing(*_args):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "pread", failing)
    with pytest.raises(OSError, match="Input/output error"):
        take(tmp_path, time_)

    assert open_descriptors() == before


@pytest.mark.parametrize("short", [False, True], ids=["enospc", "short-write"])
def test_a_start_note_that_cannot_be_written_stops_the_run_and_leaves_the_slot_as_it_was(
    tmp_path, monkeypatch, short
):
    time_ = Time()
    take(tmp_path, time_).release()
    (slot_file,) = slot_files(tmp_path)
    before = slot_file.read_bytes()
    time_.now += 100
    refuse_writes(monkeypatch, short=short)

    with pytest.raises(OSError):
        take(tmp_path, time_)

    assert slot_file.read_bytes() == before
    descriptor = os.open(slot_file, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)  # no Slot, the lock was let go
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("short", [False, True], ids=["enospc", "short-write"])
def test_a_start_note_that_cannot_be_written_is_a_refusal_of_the_destination_without_a_path(
    tmp_path, trust_ca, monkeypatch, capsys, short
):
    server = http_server.serve(0, "127.0.0.1", tls=TRUSTED)
    try:
        port = server.server_address[1]
        out = tmp_path / "runs"
        refuse_writes(monkeypatch, short=short)

        code = cli.main(
            [
                *("drive", "-q", "--http", f"https://localhost:{port}/mcp"),
                *("--out-dir", str(out), "--engagement", str(engaged(tmp_path, port))),
            ]
        )

        err = capsys.readouterr().err
        (record,) = refusals_in(out)
        assert code == 2 and record.reason == "destination"
        for text in (err, record.message):
            assert str(tmp_path) not in text, "no path, ever"
        assert server.behaviour.heads == [], "nothing connected"
        assert run_directories(out) == [], "no run directory"
    finally:
        server.shutdown()
        server.server_close()


def test_an_end_time_that_cannot_be_written_leaves_the_note_and_the_next_run_waits_in_full(
    tmp_path, monkeypatch
):
    time_ = Time()
    slot = take(tmp_path, time_)
    with monkeypatch.context() as patched:
        refuse_writes(patched, only_notes=False)
        slot.release()  # does not raise: the note stays
    (slot_file,) = slot_files(tmp_path)
    assert slot_file.read_text().startswith(pacing.START_NOTE)
    time_.now += 100

    with take(tmp_path, time_) as second:
        assert second.paced is not None and second.paced.why == "interval"
        assert second.paced.seconds == pytest.approx(10.0), "a dead run: the full interval"


@pytest.mark.parametrize("free", [True, False], ids=["free", "held"])
def test_something_in_a_slot_that_is_no_end_and_no_note_counts_as_found_and_empty_as_none(free):
    for garbage in ("start00.0\n", "started 1000000.0 af", "started", "nan", "x" * 40):
        assert pacing._end_in(garbage, free, 7.0) == 7.0, garbage
    for endless in ("inf\n", "-inf\n", "-infinity\n", "1e400\n", "-1e400\n"):
        assert pacing._end_in(endless, free, 7.0) == 7.0, endless
    assert pacing._end_in("", free, 7.0) is None
    assert pacing._end_in(" " * 128, free, 7.0) is None
    assert pacing._end_in("5.0\n", free, 7.0) == 5.0


@pytest.mark.parametrize("free", [True, False], ids=["free", "held"])
@pytest.mark.parametrize(
    "cut",
    [
        "1762299 1762300000.1 after",  # a cut-off number, then what was in the slot
        "1762299",  # no newline
        "started 12",
        "started 12 after",
        "started x after none",
        "12 13\n",
        "started 12 after 5 6\n",
        "started 12 after 5",
        "5.0 7.0\n",
    ],
)
def test_a_first_line_that_is_not_whole_or_not_one_of_the_two_forms_counts_as_found(free, cut):
    assert pacing._end_in(cut, free, 7.0) == 7.0, cut
    assert pacing._end_in(f"{cut:<128}", free, 7.0) == 7.0, "padded as a slot is"


@pytest.mark.parametrize("free", [True, False], ids=["free", "held"])
def test_only_the_first_line_is_read_and_the_clean_forms_stay_as_they_are(free):
    assert pacing._end_in("5.0\n" + " " * 124, free, 7.0) == 5.0
    assert pacing._end_in("5.0\nstarted 1.0 after none\n", free, 7.0) == 5.0
    assert pacing._end_in("1762299\n1762300000.1 after", free, 7.0) == 1762299.0
    assert pacing._end_in("", free, 7.0) is None
    assert pacing._end_in(" \n  ", free, 7.0) is None


def garbage_in_slot_one(tmp_path, time_, pacing_):
    """Slot 0 made and let go, slot 1 (not this run's) holding garbage, and a long time on."""
    take(tmp_path, time_, pacing_=pacing_).release()
    time_.now += 100
    (slot_zero,) = slot_files(tmp_path)
    slot_one = slot_zero.with_name(slot_zero.name.replace(".0.lock", ".1.lock"))
    slot_one.write_text("garbage that is no end time")
    return slot_one


def test_garbage_in_a_free_slot_that_is_not_taken_is_counted_once(tmp_path):
    time_ = Time()
    slot_one = garbage_in_slot_one(tmp_path, time_, Pacing(1, 10))

    with take(tmp_path, time_) as first:
        assert first.paced is not None and first.paced.why == "interval"
        assert first.paced.seconds == pytest.approx(10.0), "found: now"
    assert float(slot_one.read_text()) == pytest.approx(1_000_100.0), "its end, as found"
    time_.now += 100
    with take(tmp_path, time_) as second:
        assert second.paced is None, "counted once, not at every later run"


def test_garbage_in_a_slot_that_is_not_taken_does_not_refuse_every_run_after_it(tmp_path):
    time_ = Time()
    settings = Pacing(1, 60)
    slot_one = garbage_in_slot_one(tmp_path, time_, settings)

    with pytest.raises(PacingRefused, match="min_interval_seconds"):
        take(tmp_path, time_, pacing_=settings, step_timeout=30.0)
    assert float(slot_one.read_text()) == pytest.approx(1_000_100.0)
    time_.now += 61
    with take(tmp_path, time_, pacing_=settings, step_timeout=30.0) as later:
        assert later.paced is None


def test_garbage_that_cannot_be_replaced_is_counted_again_by_the_next_run(tmp_path, monkeypatch):
    time_ = Time()
    slot_one = garbage_in_slot_one(tmp_path, time_, Pacing(1, 10))
    real = os.pwrite

    def replacing_fails(descriptor, data, offset):
        if data.startswith(pacing.START_NOTE.encode()):
            return real(descriptor, data, offset)
        if descriptor_is(descriptor, slot_one):
            raise OSError(28, "No space left on device")
        return real(descriptor, data, offset)

    with monkeypatch.context() as patched:
        patched.setattr(os, "pwrite", replacing_fails)
        take(tmp_path, time_).release()  # does not raise: the replacement fails quietly
    assert slot_one.read_text() == "garbage that is no end time"
    time_.now += 100

    with take(tmp_path, time_) as second:
        assert second.paced is not None and second.paced.seconds == pytest.approx(10.0)


def descriptor_is(descriptor, path) -> bool:
    return os.path.samestat(os.fstat(descriptor), os.stat(path))


OLD_END = 1762299990.5  # the end a slot holds
NOW = 1762300000.25  # a run starts: the digits carry over from the end above


def cutting(monkeypatch, note=None, other=None):
    """``os.pwrite`` that really writes only the first ``note`` bytes of a start note and the first
    ``other`` bytes of any other write (an end time, a put-back), and says how many it wrote. The
    writes are listed in the result, whole."""
    real = os.pwrite
    writes: list[bytes] = []

    def short(descriptor, data, offset):
        writes.append(data)
        count = note if data.startswith(pacing.START_NOTE.encode()) else other
        return real(descriptor, data[:count], offset)

    monkeypatch.setattr(os, "pwrite", short)
    return writes


def padded(text):
    return f"{text:<{pacing._WIDTH}}"


def slot_with_end(out, before):
    """A slot that held the end ``OLD_END`` (``before``) or is new, the clock at ``NOW``."""
    time_ = Time(OLD_END)
    if before:
        take(out, time_).release()
    time_.now = NOW
    return time_


@pytest.mark.parametrize("before", [True, False], ids=["end-in-slot", "new-slot"])
def test_a_start_note_cut_short_writes_nothing_back_and_the_next_run_waits_in_full(
    tmp_path, monkeypatch, before
):
    note = padded(pacing._note(NOW, OLD_END if before else None))
    for k in range(len(note)):
        out = tmp_path / f"{k}"
        time_ = slot_with_end(out, before)
        with monkeypatch.context() as patched:
            writes = cutting(patched, note=k)
            with pytest.raises(OSError):
                take(out, time_)
        assert len(writes) == 1, f"{k=}: a second write"
        (slot_file,) = slot_files(out)
        old = padded(f"{OLD_END!r}\n") if before else ""
        assert slot_file.read_text() == note[:k] + old[k:], k

        with take(out, time_) as second:
            if k == 0 and not before:
                assert second.paced is None, "nothing was written, nothing was there"
                continue
            assert second.paced is not None and second.paced.why == "interval", k
            # k = 0 left the old end; any other k left something found, 10 s from the next run
            expected = OLD_END + 10 - NOW if k == 0 else 10.0
            assert second.paced.seconds == pytest.approx(expected), k


def test_the_cut_of_the_finding_leaves_no_early_end_and_the_next_run_waits_in_full(
    tmp_path, monkeypatch
):
    time_ = slot_with_end(tmp_path, True)
    with monkeypatch.context() as patched:
        writes = cutting(patched, note=10, other=8)
        with pytest.raises(OSError):
            take(tmp_path, time_)
    (slot_file,) = slot_files(tmp_path)
    content = slot_file.read_text()
    assert len(writes) == 1, "no put-back of 8 bytes over the rest"
    assert content.split("\n")[0] == "started 17.5", "the end time is not a word with a newline"
    assert content.split()[0] != "1762299917.5"

    with take(tmp_path, time_) as second:
        assert second.paced is not None and second.paced.why == "interval"
        assert second.paced.seconds == pytest.approx(10.0), "73 s early would be no wait at all"


@pytest.mark.parametrize("before", [True, False], ids=["end-in-slot", "new-slot"])
def test_a_slot_put_back_after_a_whole_note_and_cut_short_never_lets_the_next_run_go_early(
    tmp_path, monkeypatch, before
):
    settings = Pacing(1 if before else 2, 60)
    for j in range(pacing._WIDTH):
        out = tmp_path / f"{j}"
        time_ = Time(OLD_END)
        if before:
            take(out, time_, pacing_=settings).release()
        else:
            # slot 1 holds the end that makes the run refuse; slot 0 is new
            directory = out / ".pacing"
            directory.mkdir(parents=True, mode=0o700)
            digest = hashlib.sha256(pacing.origin_of(URL).encode()).hexdigest()
            pacing._path(directory, digest, 1).write_text(f"{OLD_END!r}\n")
        time_.now = NOW
        with monkeypatch.context() as patched:
            cutting(patched, other=j)
            with pytest.raises(PacingRefused):
                take(out, time_, pacing_=settings, step_timeout=5.0)  # 50 s: refused, put back
        (slot_file,) = [path for path in slot_files(out) if path.name.endswith(".0.lock")]
        content = slot_file.read_text()

        # Put back whole, the slot holds its old end, or is empty again and slot 1 holds that end:
        # the run waits what that end asks. Anything else left over counts as found: the full 60 s.
        # An end time that is too early would be neither, and in this slot alone it would show.
        whole = content.split("\n")[0] == repr(OLD_END) if before else not content.strip()
        with take(out, time_, pacing_=settings, step_timeout=100.0) as second:
            assert second.paced is not None and second.paced.why == "interval", f"{j=} {content!r}"
            expected = OLD_END + 60 - NOW if whole else 60.0
            assert second.paced.seconds == pytest.approx(expected), f"{j=} {content!r}"


def test_no_cut_of_an_end_time_lets_the_next_run_go_early(tmp_path, monkeypatch):
    for j in range(pacing._WIDTH):
        out = tmp_path / f"{j}"
        time_ = slot_with_end(out, True)
        slot = take(out, time_)  # it waits 0.25 s, then runs
        time_.now += 3
        with monkeypatch.context() as patched:
            cutting(patched, other=j)
            slot.release()
        (slot_file,) = slot_files(out)
        content = slot_file.read_text()
        with take(out, time_) as second:
            assert second.paced is not None and second.paced.why == "interval", f"{j=} {content!r}"
            # the end of the run just let go is now, or what is left is found: now
            assert second.paced.seconds == pytest.approx(10.0), f"{j=} {content!r}"


def test_a_held_note_that_says_after_none_is_still_no_end():
    assert pacing._end_in("started 9.0 after none\n", False, 7.0) is None
    assert pacing._end_in("started 9.0 after 4.0\n", False, 7.0) == 4.0


def hold_origin_lock(out_dir) -> int:
    """Another process's flock on ``<digest>.lock`` (a second descriptor does the same)."""
    digest = hashlib.sha256(pacing.origin_of(URL).encode()).hexdigest()
    descriptor = os.open(Path(out_dir) / ".pacing" / f"{digest}.lock", os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return descriptor


def bounded(function, seconds=5.0):
    """``function()`` in a daemon thread: a ``flock`` that blocks without end fails the test
    instead of hanging the suite."""
    outcome = {}

    def target():
        try:
            outcome["value"] = function()
        except BaseException as error:  # noqa: BLE001 - handed to the test
            outcome["error"] = error

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"did not return within {seconds:g} s: blocked on a lock"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def test_an_origin_lock_that_is_held_refuses_the_run_at_the_step_timeout(tmp_path):
    time_ = Time()
    take(tmp_path, time_, pacing_=Pacing(1, 0)).release()
    (slot_file,) = slot_files(tmp_path)
    before = slot_file.read_bytes()
    holder = hold_origin_lock(tmp_path)
    try:
        with pytest.raises(PacingRefused) as refused:
            bounded(lambda: take(tmp_path, time_, step_timeout=2.0))
    finally:
        os.close(holder)

    assert str(refused.value) == (
        f"the slots of {pacing.origin_of(URL)} are locked by another process and did not free "
        "within --step-timeout (2 s); nothing was started"
    )
    assert str(tmp_path) not in str(refused.value)
    assert time_.slept == pytest.approx([pacing.POLL_SECONDS] * len(time_.slept))
    assert time_.now >= 1_000_000.0 + 2.0, "it waited the step timeout, on the clock"
    assert slot_file.read_bytes() == before


def test_an_origin_lock_that_is_let_go_before_the_step_timeout_lets_the_run_go_on(tmp_path):
    time_ = Time()
    take(tmp_path, time_, pacing_=Pacing(1, 0)).release()
    holder = hold_origin_lock(tmp_path)
    polls = []

    def let_go_after_three_polls(seconds: float) -> None:
        time_.sleep(seconds)
        polls.append(seconds)
        if len(polls) == 3:
            os.close(holder)

    slot = bounded(
        lambda: pacing.acquire(
            tmp_path, URL, Pacing(1, 0), 30.0, clock=time_, sleep=let_go_after_three_polls
        )
    )
    with slot:
        assert slot.paced is None, "waiting for the lock is not waiting for the origin"
        assert len(polls) == 3
        assert slot_files(tmp_path)[0].read_text().startswith(pacing.START_NOTE)


def test_an_origin_lock_held_while_a_refusal_is_cleaned_up_changes_nothing_and_hangs_nothing(
    tmp_path, monkeypatch
):
    time_ = Time()
    take(tmp_path, time_).release()
    time_.now += 1  # the interval is open: the next run would wait 9 s
    holders = []
    armed = []
    real_take = pacing._take

    def arming(*args):
        taken = real_take(*args)
        armed.append(True)
        return taken

    def clock() -> float:
        if armed and not holders:
            holders.append(hold_origin_lock(tmp_path))  # after the note, before the refusal
        return time_()

    monkeypatch.setattr(pacing, "_take", arming)
    slept_before = len(time_.slept)
    try:
        with pytest.raises(PacingRefused, match="min_interval_seconds"):
            bounded(
                lambda: pacing.acquire(
                    tmp_path, URL, Pacing(1, 10), 5.0, clock=clock, sleep=time_.sleep
                )
            )
    finally:
        os.close(holders[0])

    assert len(time_.slept) - slept_before == pacing.CLEANUP_ATTEMPTS - 1, "five tries, no more"
    (slot_file,) = slot_files(tmp_path)
    assert slot_file.read_text().startswith(pacing.START_NOTE), "not put back"
    monkeypatch.undo()
    time_.now += 50
    with take(tmp_path, time_) as second:
        assert second.paced is not None and second.paced.seconds == pytest.approx(10.0)


# -- an initialize sent again after a Retry-After wait is still the first --------------------

EVENT = b"event: endpoint\ndata: /elsewhere/messages?sessionId=1\n\n"
HELLO = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26", "capabilities": {}}}


def initialize_answered(second, old_transport, *, first_answer=429):
    """A stub: ``initialize`` is answered ``first_answer`` (429 with ``Retry-After: 1``, or 200),
    the next ``initialize`` with ``second``; a GET opens the old transport's stream, or is 405."""
    posts = []

    def reply(connection, seen):
        if seen.method == "GET":
            if old_transport:
                connection.sendall(http(200, EVENT, kind="text/event-stream"))
            else:
                connection.sendall(http(405))
        elif json.loads(seen.body).get("method") != "initialize":
            connection.sendall(http(200, b"{}"))
        else:
            posts.append(seen)
            if len(posts) == 1 and first_answer == 429:
                connection.sendall(http(429, extra="Retry-After: 1\r\n"))
            elif len(posts) == 1:
                connection.sendall(http(200, json.dumps(HELLO).encode()))
            else:
                connection.sendall(http(second))

    return reply


@pytest.mark.parametrize("second", [400, 404, 405])
def test_an_initialize_sent_again_after_a_wait_on_an_endpoint_of_the_old_transport_is_sse_only(
    stub, waits, second
):
    server = stub(initialize_answered(second, old_transport=True))

    run = drive(server.url)

    assert waits == [1]
    assert run.outcome.server_failed == HTTP_SSE_ONLY
    assert [seen.method for seen in server.requests] == ["POST", "POST", "GET"]


def test_an_initialize_sent_again_after_a_wait_on_an_endpoint_without_the_old_transport_is_status(
    stub, waits
):
    server = stub(initialize_answered(405, old_transport=False))

    run = drive(server.url)

    assert waits == [1]
    assert run.outcome.server_failed == HTTP_STATUS
    assert [seen.method for seen in server.requests] == ["POST", "POST", "GET"], "it was probed"


def test_an_initialize_that_was_answered_before_is_not_probed_when_it_gets_a_405(stub):
    server = stub(initialize_answered(405, old_transport=True, first_answer=200))
    line = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'

    async def converse() -> None:
        channel = HttpClientChannel(server.url)
        await channel.send(line)
        assert await channel.read_line(5.0)
        await channel.send(line)  # a second initialize, not the first
        await channel.read_line(5.0)
        channel.close()
        assert channel.failure == "http_status"

    asyncio.run(converse())

    assert [seen.method for seen in server.requests] == ["POST", "POST"], "no GET: not probed"


def test_an_initialize_that_was_answered_before_is_not_probed_when_its_resend_gets_a_405(stub):
    posts = []

    def reply(connection, seen):
        if seen.method == "GET":
            connection.sendall(http(200, EVENT, kind="text/event-stream"))
            return
        posts.append(seen)
        if len(posts) == 1:
            connection.sendall(http(200, json.dumps(HELLO).encode()))
        elif len(posts) == 2:
            connection.sendall(http(429, extra="Retry-After: 1\r\n"))
        else:
            connection.sendall(http(405))

    server = stub(reply)
    line = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'

    async def converse() -> None:
        channel = HttpClientChannel(server.url)
        await channel.send(line)
        assert await channel.read_line(5.0)
        await channel.send(line)  # a second initialize, not the first: answered 429
        await channel.read_line(5.0)
        channel.after_wait = True  # what the driver does around the one it sends again
        await channel.send(line)
        await channel.read_line(5.0)
        channel.close()
        assert channel.failure == "http_status"

    asyncio.run(converse())
    assert [seen.method for seen in server.requests] == ["POST", "POST", "POST"], "no probe"
