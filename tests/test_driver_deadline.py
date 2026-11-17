"""One time per step: the wait for an answer ends ``step_timeout`` after the request was
sent, however many other lines the server sends in between."""

from __future__ import annotations

import asyncio
import json
import time

from mcp_kymograph.driver import DISCOVERY, Driver
from mcp_kymograph.events import NO_ANSWER

STEP_TIMEOUT = 0.05
STRAY = b'{"jsonrpc": "2.0", "id": 9999, "result": {}}\n'
HELLO = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "serverInfo": {"name": "s", "version": "1"},
}


class _Drip:
    """A server that sends a line that matches nothing shortly before each time runs out.

    It gives up by itself after ``cap`` seconds, so that a driver without one time per step
    ends the test instead of hanging it."""

    def __init__(self, cap: float = 2.0) -> None:
        self.sent: list[dict] = []
        self.reads: list[float] = []
        self._cap = cap
        self._began: float | None = None

    async def open(self) -> None:
        return None

    async def send(self, line: bytes) -> None:
        self.sent.append(json.loads(line))
        if self._began is None:
            self._began = time.monotonic()

    async def read_line(self, timeout: float) -> bytes | None:
        self.reads.append(timeout)
        assert self._began is not None
        if time.monotonic() - self._began > self._cap:
            raise asyncio.TimeoutError
        await asyncio.sleep(timeout * 0.9)
        return STRAY

    def close_write(self) -> None:
        return None


class _Late(_Drip):
    """Strays, each taking a little of the time, then the real answer, all within the time."""

    def __init__(self, strays: int) -> None:
        super().__init__()
        self._strays = strays

    async def read_line(self, timeout: float) -> bytes | None:
        self.reads.append(timeout)
        if self._strays:
            self._strays -= 1
            await asyncio.sleep(STEP_TIMEOUT / 10)
            return STRAY
        return (
            json.dumps({"jsonrpc": "2.0", "id": self.sent[-1]["id"], "result": HELLO}).encode()
            + b"\n"
        )


def _drive(wire) -> tuple[list, float]:
    failed, took, _, _ = _drive_all(wire)
    return failed, took


def _drive_all(wire):
    """What was recorded as failed, how long it took, the outcome, and what was skipped."""
    failed: list = []
    skipped: list = []

    async def record_failed(**fields) -> None:
        failed.append(fields)

    async def record_skipped(**fields) -> None:
        skipped.append(fields)

    driver = Driver(
        DISCOVERY,
        wire,
        record_skipped=record_skipped,
        record_failed=record_failed,
        step_timeout=STEP_TIMEOUT,
    )
    began = time.monotonic()
    outcome = asyncio.run(driver.run())
    return failed, time.monotonic() - began, outcome, skipped


def test_lines_that_match_nothing_do_not_extend_the_time_of_a_step():
    wire = _Drip()
    failed, took = _drive(wire)
    assert took < 0.5  # not MAX_INTERLEAVED * STEP_TIMEOUT, which is 50 s
    assert [entry["reason"] for entry in failed] == [NO_ANSWER]
    assert all(read <= STEP_TIMEOUT for read in wire.reads)


def test_no_line_is_read_with_a_time_of_zero_or_less():
    wire = _Drip()
    _drive(wire)
    assert wire.reads and all(read > 0 for read in wire.reads)


def test_an_answer_after_some_other_lines_within_the_time_is_the_answer():
    # Five strays take half of the time; the answer after them is still the answer: the
    # handshake completes, nothing failed or was skipped for a fault of the driver's.
    wire = _Late(strays=5)
    failed, _, outcome, skipped = _drive_all(wire)
    assert failed == []
    assert outcome.server_failed is None
    assert outcome.protocol_version == "2025-06-18"
    assert not any(entry["reason"] == "driver_error" for entry in skipped)
    assert all(read > 0 for read in wire.reads)
