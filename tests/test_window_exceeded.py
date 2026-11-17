"""``run_finished.window_exceeded``: whether a run outlasted its engagement's window.

Recorded, and for what the tool only observes never acted on: a proxied run that starts inside
the window and ends outside it is not cut short, and nothing judged reads the field — the same
recording with it true, false or absent has the same state. What the tool drives itself ends with
the window (tests/test_active_probes.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_kymograph import verdict
from mcp_kymograph.authorization import Declaration
from mcp_kymograph.events import Mode
from mcp_kymograph.http_proxy import HttpProxy
from mcp_kymograph.masking import Masker
from mcp_kymograph.proxy import Limits, Proxy
from mcp_kymograph.recorder import Recorder

FIXTURES = Path(__file__).parent / "fixtures"
TOY = str(FIXTURES / "toy_server.py")
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

UNTIL = datetime(2026, 11, 7, 18, tzinfo=timezone.utc)
ENGAGED = Declaration(
    engagement_id_declared="acme-2026-10",
    engagement_digest="ab" * 32,
    window_declared={"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
)
INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode() + b"\n"
LIMITS = Limits(max_duration_seconds=30.0, terminate_grace_seconds=0.5, shutdown_budget_seconds=3.0)


class Clock:
    """A wall clock a test moves: before the window's end until told otherwise."""

    def __init__(self) -> None:
        self.now = UNTIL - timedelta(minutes=5)

    def __call__(self) -> datetime:
        return self.now


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def finished_of(path: Path) -> dict:
    (finished,) = [e for e in events_of(path) if e["type"] == "run_finished"]
    return finished


# -- the recording ---------------------------------------------------------------------------


def test_the_field_is_written_as_given_and_null_without_it(tmp_path):
    path = tmp_path / "events.jsonl"
    closing = {"server_output_bytes": 0, "client_input_bytes": 0, "server_exited_first": False}
    with Recorder.open(path, run_id="window", masker=Masker()) as recorder:
        recorder.run_finished(1, 1, reason="client_eof", duration_ns=5, window_exceeded=True,
                              **closing)  # fmt: skip
        recorder.run_finished(2, 2, reason="client_eof", duration_ns=5, window_exceeded=False,
                              **closing)  # fmt: skip
        recorder.run_finished(3, 3, reason="client_eof", duration_ns=5, **closing)
    assert [e["window_exceeded"] for e in events_of(path)] == [True, False, None]


@pytest.mark.parametrize("value", [True, False, None, "absent"])
def test_nothing_judged_reads_it(value):
    started = {"type": "run_started", "mode": "driver", "isolation": "host"}
    ended = {"type": "script_finished", "inventory": "complete"}
    finished = {
        "type": "run_finished",
        "findings_by_statement": {},
        "server_output_bytes": 100,
        "client_input_bytes": 100,
        "server_exited_first": False,
    }
    baseline = verdict.assess([started, ended, finished])
    if value != "absent":
        finished = {**finished, "window_exceeded": value}
    judged = verdict.assess([started, ended, finished])
    assert (judged.state, judged.exit_code, judged.problems, judged.causes) == (
        baseline.state,
        baseline.exit_code,
        baseline.problems,
        baseline.causes,
    )


def test_the_declaration_reads_the_end_of_its_window():
    assert ENGAGED.window_until() == UNTIL
    assert Declaration().window_until() is None


@pytest.mark.parametrize(
    ("moment", "exceeded"),
    [
        (UNTIL - timedelta(microseconds=1), False),
        (UNTIL, True),  # where the gate refuses a run: now >= until
        (UNTIL + timedelta(microseconds=1), True),
    ],
)
def test_the_end_of_the_window_is_where_the_gate_draws_it(tmp_path, moment, exceeded):
    clock = Clock()
    clock.now = moment
    with Recorder.open(tmp_path / "events.jsonl", run_id="window", masker=Masker()) as recorder:
        proxy = Proxy(argv=["x"], recorder=recorder, limits=LIMITS, client_in=None,
                      client_out=None, declaration=ENGAGED, clock=clock)  # fmt: skip
        assert proxy.window_exceeded() is exceeded


# -- the stdio closing path ------------------------------------------------------------------


async def stdio_run(path: Path, declaration: Declaration, clock: Clock, *, pass_the_end: bool):
    """One proxied session with the toy server: one request, its answer, the client leaves.
    With ``pass_the_end``, the clock passes the window's end between the answer and the close."""
    to_proxy_read, to_proxy = os.pipe()
    from_proxy, from_proxy_write = os.pipe()
    client_in = os.fdopen(to_proxy_read, "rb", buffering=0)
    client_out = os.fdopen(from_proxy_write, "wb", buffering=0)
    received = os.fdopen(from_proxy, "rb", buffering=0)
    with Recorder.open(path, run_id="window", masker=Masker()) as recorder:
        proxy = Proxy(
            argv=[sys.executable, TOY, "--mode", "normal"],
            recorder=recorder,
            limits=LIMITS,
            client_in=client_in,
            client_out=client_out,
            declaration=declaration,
            clock=clock,
        )
        task = asyncio.create_task(proxy.run())
        os.write(to_proxy, INITIALIZE)
        answer = await asyncio.wait_for(asyncio.to_thread(received.readline), 10)
        assert json.loads(answer)["id"] == 1
        if pass_the_end:
            clock.now = UNTIL  # the end itself: the moment the gate refuses from
        os.close(to_proxy)
        outcome = await asyncio.wait_for(task, 20)
    for handle in (client_in, client_out, received):
        with contextlib.suppress(OSError):
            handle.close()
    return outcome


def test_a_run_whose_clock_passes_the_end_mid_run_records_it_and_keeps_its_state(tmp_path):
    inside, outside = tmp_path / "inside.jsonl", tmp_path / "outside.jsonl"
    within = asyncio.run(stdio_run(inside, ENGAGED, Clock(), pass_the_end=False))
    beyond = asyncio.run(stdio_run(outside, ENGAGED, Clock(), pass_the_end=True))
    assert finished_of(inside)["window_exceeded"] is False
    assert finished_of(outside)["window_exceeded"] is True
    assert beyond.reason == within.reason, "not cut short: it ended as the other did"
    assert beyond.exit_code == within.exit_code
    assert verdict.read(outside).state == verdict.read(inside).state
    assert verdict.read(outside).problems == verdict.read(inside).problems


def test_a_run_without_a_file_records_null(tmp_path):
    path = tmp_path / "events.jsonl"
    asyncio.run(stdio_run(path, Declaration(), Clock(), pass_the_end=True))
    assert finished_of(path)["window_exceeded"] is None
    assert events_of(path)[0]["authorization"]["engagement"] is None


def test_a_server_that_never_started_records_it_too(tmp_path):
    """The closing path of a run without a server writes the field like the others."""
    path = tmp_path / "events.jsonl"
    clock = Clock()
    clock.now = UNTIL + timedelta(hours=1)

    async def run():
        with Recorder.open(path, run_id="window", masker=Masker()) as recorder:
            proxy = Proxy(
                argv=[str(tmp_path / "no-such-server")],
                recorder=recorder,
                limits=LIMITS,
                client_in=None,
                client_out=None,
                declaration=ENGAGED,
                clock=clock,
                mode=Mode.DRIVER,
            )
            return await asyncio.wait_for(proxy.run(), 20)

    outcome = asyncio.run(run())
    assert outcome.reason == "server_not_started"
    assert finished_of(path)["window_exceeded"] is True


# -- the HTTP closing path -------------------------------------------------------------------


@pytest.fixture
def served():
    server = http_server.serve(0)
    yield f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
    server.shutdown()
    server.server_close()


async def http_run(path: Path, url: str, clock: Clock, *, pass_the_end: bool):
    with Recorder.open(path, run_id="window", masker=Masker()) as recorder:
        proxy = HttpProxy(
            endpoint=url,
            recorder=recorder,
            limits=Limits(),
            mode=Mode.DRIVER,
            declaration=ENGAGED,
            clock=clock,
        )
        settled = asyncio.Event()
        proxy.client_settled = settled

        async def converse():
            try:
                await proxy.launched.wait()
                reader, writer = await proxy.front_connect()
                body = INITIALIZE.rstrip(b"\n")
                writer.write(
                    b"POST " + http_server.PATH.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Accept: application/json, text/event-stream\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                await writer.drain()
                await asyncio.wait_for(reader.read(), 10)
                writer.close()
                if pass_the_end:
                    clock.now = UNTIL  # the end itself: the moment the gate refuses from
            finally:
                settled.set()

        task = asyncio.create_task(converse())
        outcome = await proxy.run()
        await task
    return outcome


def test_the_http_closing_path_writes_it(tmp_path, served):
    inside, outside = tmp_path / "inside.jsonl", tmp_path / "outside.jsonl"
    asyncio.run(http_run(inside, served, Clock(), pass_the_end=False))
    asyncio.run(http_run(outside, served, Clock(), pass_the_end=True))
    assert finished_of(inside)["window_exceeded"] is False
    assert finished_of(outside)["window_exceeded"] is True
    assert verdict.read(outside).state == verdict.read(inside).state


# -- run_started.pacing_enforced -------------------------------------------------------------


def started_of(path: Path) -> dict:
    return events_of(path)[0]


def test_pacing_enforced_is_written_as_given_and_null_without_it(tmp_path):
    path = tmp_path / "events.jsonl"
    with Recorder.open(path, run_id="pacing", masker=Masker()) as recorder:
        recorder.run_started(1, 1, argv=["srv"], limits={}, pacing_enforced=False)
        recorder.run_started(2, 2, argv=["srv"], limits={})
    assert [e["pacing_enforced"] for e in events_of(path)] == [False, None]


def test_the_declaration_says_nothing_of_pacing():
    """Whether a run was paced is the run's (mcp_kymograph.pacing), not the declaration's."""
    assert not hasattr(ENGAGED, "pacing_enforced")
    assert "pacing_enforced" not in ENGAGED.as_dict(), "beside authorization, not in it"


def test_a_stdio_run_under_a_file_records_no_pacing_and_nothing_else_of_the_file(
    tmp_path,
):
    from mcp_kymograph import engagement

    path = tmp_path / "e.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "id": "acme-2026-10",
                "customer": "CANARY-CUSTOMER",
                "reference": "CANARY-REFERENCE",
                "contacts": [{"name": "CANARY-CONTACT"}],
                "window": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
                "targets": [{"host": "localhost"}],
                "actions": {"list": True, "call": False},
                "pacing": {"runs_per_origin": 7, "min_interval_seconds": 4242},
                "redaction": {"mask_keys": ["CANARY-KEY"], "mask_patterns": ["CANARY-PATTERN"]},
            }
        )
    )
    loaded = engagement.load(path)
    declaration = Declaration(**engagement.declaration_fields(loaded))
    recording = tmp_path / "events.jsonl"
    asyncio.run(stdio_run(recording, declaration, Clock(), pass_the_end=False))
    started = started_of(recording)
    assert started["pacing_enforced"] is None
    assert started["pacing"] is None
    assert started["authorization"]["engagement"] == engagement.declaration_fields(loaded)
    assert set(started["authorization"]["engagement"]) == {
        "engagement_id_declared",
        "engagement_digest",
        "window_declared",
    }
    text = recording.read_text()
    for value in ("CANARY", "runs_per_origin", "min_interval_seconds"):
        assert value not in text


def test_a_run_without_a_file_records_pacing_enforced_null(tmp_path):
    path = tmp_path / "events.jsonl"
    asyncio.run(stdio_run(path, Declaration(), Clock(), pass_the_end=False))
    assert started_of(path)["pacing_enforced"] is None


def test_the_http_proxy_to_loopback_records_null_too(tmp_path, served):
    path = tmp_path / "events.jsonl"
    asyncio.run(http_run(path, served, Clock(), pass_the_end=False))
    assert started_of(path)["pacing_enforced"] is None
    assert started_of(path)["pacing"] is None


@pytest.mark.parametrize("value", [False, None, "absent"])
def test_nothing_judged_reads_pacing_enforced(value):
    started = {"type": "run_started", "mode": "driver", "isolation": "host"}
    ended = {"type": "script_finished", "inventory": "complete"}
    finished = {
        "type": "run_finished",
        "findings_by_statement": {},
        "server_output_bytes": 100,
        "client_input_bytes": 100,
        "server_exited_first": False,
    }
    baseline = verdict.assess([started, ended, finished])
    if value != "absent":
        started = {**started, "pacing_enforced": value}
    judged = verdict.assess([started, ended, finished])
    assert (judged.state, judged.exit_code, judged.problems, judged.causes) == (
        baseline.state,
        baseline.exit_code,
        baseline.problems,
        baseline.causes,
    )
