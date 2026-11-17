"""The queue between observation and the file.

Run with ``asyncio.run`` inside plain tests rather than pytest-asyncio: the project carries
no runtime dependencies, and at zero of those a development dependency that executes code in
CI is attack surface a security tool would have to explain.
"""

import asyncio
import inspect
import threading
import time

import pytest

from mcp_kymograph.sink import EventSink


class Writer:
    """Stands in for the recorder. Records what reached it, in the order it arrived."""

    def __init__(self, *, fail_from: int | None = None) -> None:
        self.written: list[tuple[int, str]] = []
        self.fail_from = fail_from
        self._lock = threading.Lock()

    def emitter(self, kind: str):
        def emit(seq: int, _t_ns: int) -> None:
            if self.fail_from is not None and seq >= self.fail_from:
                raise OSError("no space left on device")
            with self._lock:
                self.written.append((seq, kind))

        return emit

    @property
    def sequences(self) -> list[int]:
        with self._lock:
            return [seq for seq, _ in self.written]

    @property
    def kinds(self) -> list[str]:
        with self._lock:
            return [kind for _, kind in self.written]


def run(scenario) -> None:
    asyncio.run(scenario())


async def settled(sink: EventSink, *, timeout: float = 2.0) -> None:
    """Wait until the writer thread has caught up."""
    deadline = time.monotonic() + timeout
    while sink.queued and time.monotonic() < deadline:
        await asyncio.sleep(0.001)


# -- the property the writer thread exists for ----------------------------------------


def test_a_blocking_write_never_stalls_the_forwarding_path():
    """The measurement that found the flaw, kept as a test.

    Writing is synchronous, and a flush on a wedged filesystem does not raise — it simply
    does not return. On the event loop that stops every pump with it, and encapsulation
    does not help, because try/except catches exceptions rather than failure to return.
    This is not readable from the code, so only a test protects it across the next rewrite.
    """
    release = threading.Event()

    def wedged(_seq: int, _t_ns: int) -> None:
        release.wait(5.0)

    async def scenario():
        sink = EventSink(queue_size=10)
        sink.start()
        sink.offer(wedged, kind="message")

        ticks: list[float] = []
        start = time.monotonic()
        while time.monotonic() - start < 0.5:  # stands in for the forwarding pumps
            ticks.append(time.monotonic())
            await asyncio.sleep(0.005)
        release.set()
        await sink.drain(timeout=2)
        return ticks

    ticks = asyncio.run(scenario())
    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:], strict=False)]
    assert max(gaps) < 0.1, f"forwarding stalled for {max(gaps):.3f}s behind a blocking write"


# -- numbering ------------------------------------------------------------------------


def test_a_dropped_event_still_consumes_its_number():
    """Something has to be written *after* the drop, or there is no jump to see."""
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=1)
        assert sink.offer(writer.emitter("a"), kind="message") is True  # seq 1
        assert sink.offer(writer.emitter("b"), kind="message") is False  # seq 2, dropped
        assert sink.offer(writer.emitter("c"), kind="message") is False  # seq 3, dropped
        sink.start()
        await settled(sink)
        assert sink.offer(writer.emitter("d"), kind="message") is True  # seq 4
        await sink.drain(timeout=2)

    run(scenario)
    assert writer.sequences == [1, 4], "the two dropped numbers must not be reused"


def test_the_drop_counter_matches_the_gap():
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=1)
        for _ in range(5):
            sink.offer(writer.emitter("message"), kind="message")
        sink.start()
        await sink.drain(timeout=2)
        return sink

    sink = asyncio.run(scenario())
    assert sink.dropped == 4
    assert writer.sequences == [1]


def test_timestamps_are_taken_on_the_way_in():
    stamps: list[int] = []
    clock = iter(range(1000, 100000, 1000))

    async def scenario():
        sink = EventSink(queue_size=4, clock=lambda: next(clock))
        for _ in range(3):
            sink.offer(lambda _s, t: stamps.append(t), kind="message")
        sink.start()
        await sink.drain(timeout=2)

    run(scenario)
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == 3


# -- the ordering invariant -----------------------------------------------------------


def test_offer_drops_while_a_waiter_is_pending_even_once_there_is_room():
    """The race this invariant exists for, made deterministic.

    The waiting non-droppable event is given a poll interval long enough that it cannot
    retry during the test, so room genuinely exists and only the invariant can stop an
    offer from taking it. Without the invariant the later event lands in the file with a
    higher number before the lower one, and gap detection reads nonsense.
    """
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=1, wait_poll_seconds=30.0)
        sink.offer(writer.emitter("first"), kind="message")  # seq 1, queue full

        waiter = asyncio.create_task(sink.put(writer.emitter("lifecycle"), kind="life"))
        await asyncio.sleep(0)
        assert sink.waiting == 1, "precondition: the lifecycle event is waiting"

        sink.start()
        await settled(sink)
        assert sink.queued == 0, "precondition: there is room now"
        assert sink.waiting == 1, "precondition: the waiter has not retried yet"

        late = sink.offer(writer.emitter("late"), kind="message")

        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)
        await sink.drain(timeout=2)
        return late

    assert asyncio.run(scenario()) is False, "an offer must not overtake a pending waiter"


def test_a_second_lifecycle_event_gets_no_number_until_the_first_is_queued():
    """The serial gate, observed directly rather than raced."""
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=1, wait_poll_seconds=30.0)
        sink.offer(writer.emitter("message"), kind="message")  # seq 1, queue full

        first = asyncio.create_task(sink.put(writer.emitter("exited"), kind="life"))
        await asyncio.sleep(0)
        assert sink.assigned == 2, "the first waiter took its number inside the gate"

        second = asyncio.create_task(sink.put(writer.emitter("limit"), kind="life"))
        await asyncio.sleep(0)
        assert sink.assigned == 2, "the second waiter must still be held at the gate"

        for task in (first, second):
            task.cancel()
        await asyncio.gather(first, second, return_exceptions=True)

    run(scenario)


def test_a_non_droppable_event_is_never_dropped():
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=1)
        sink.start()
        for index in range(20):
            await sink.put(writer.emitter(f"life{index}"), kind="life")
        await sink.drain(timeout=3)
        return sink

    sink = asyncio.run(scenario())
    assert sink.dropped == 0
    assert len(writer.written) == 20


# -- stalling -------------------------------------------------------------------------


def test_a_write_failure_stops_observation_once_and_reports_where():
    writer = Writer(fail_from=2)
    stalls: list[tuple[int, str]] = []
    seen = threading.Lock()

    def record(seq: int, reason: str) -> None:
        with seen:
            stalls.append((seq, reason))

    async def scenario():
        sink = EventSink(queue_size=10, on_stall=record)
        sink.start()
        for _ in range(5):
            sink.offer(writer.emitter("message"), kind="message")
            await settled(sink)
        await sink.drain(timeout=2)
        return sink

    sink = asyncio.run(scenario())
    assert sink.stalled is True
    assert stalls == [(2, "write_failed")]  # reported once, with the first blind number
    assert writer.written == [(1, "message")]


def test_a_stalled_sink_stops_accepting_rather_than_retrying():
    writer = Writer(fail_from=1)

    async def scenario():
        sink = EventSink(queue_size=10)
        sink.start()
        sink.offer(writer.emitter("message"), kind="message")
        await settled(sink)
        while not sink.stalled:
            await asyncio.sleep(0.001)
        accepted = [sink.offer(writer.emitter("message"), kind="message") for _ in range(3)]
        await sink.drain(timeout=2)
        return accepted

    assert asyncio.run(scenario()) == [False, False, False]


def test_observation_can_be_stopped_from_outside():
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=10)
        sink.stop_observing(from_seq=7, reason="observer_error")
        assert sink.offer(writer.emitter("message"), kind="message") is False
        return sink

    assert asyncio.run(scenario()).stalled is True


def test_a_stall_callback_that_itself_fails_does_not_escape():
    def explode(_seq: int, _reason: str) -> None:
        raise RuntimeError("stderr is gone too")

    async def scenario():
        sink = EventSink(queue_size=10, on_stall=explode)
        sink.stop_observing(from_seq=1, reason="write_failed")
        return sink

    assert asyncio.run(scenario()).stalled is True


# -- the final write ------------------------------------------------------------------


def test_run_finished_is_written_even_after_a_stall():
    """The ending is exempt: a recording that stops without one is the failure the drain
    deadline exists to prevent."""
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=10)
        sink.stop_observing(from_seq=1, reason="write_failed")
        return await sink.write_final(writer.emitter("run_finished"), kind="run_finished")

    assert asyncio.run(scenario()) is True
    assert writer.kinds == ["run_finished"]


def test_a_failing_final_write_is_not_an_error():
    writer = Writer(fail_from=1)

    async def scenario():
        sink = EventSink(queue_size=10)
        return await sink.write_final(writer.emitter("run_finished"), kind="run_finished")

    assert asyncio.run(scenario()) is False


def test_a_final_write_that_hangs_is_abandoned_rather_than_hanging_shutdown():
    release = threading.Event()

    def wedged(_seq: int, _t_ns: int) -> None:
        release.wait(30)

    async def scenario():
        sink = EventSink(queue_size=10)
        started = time.monotonic()
        written = await sink.write_final(wedged, kind="run_finished", timeout=0.1)
        return written, time.monotonic() - started

    try:
        written, elapsed = asyncio.run(scenario())
    finally:
        release.set()

    assert written is False
    assert elapsed < 5, "shutdown must not wait for a write that will not return"


def test_a_final_write_is_attempted_only_once():
    attempts = []

    def failing(seq: int, _t_ns: int) -> None:
        attempts.append(seq)
        raise OSError("no space left on device")

    async def scenario():
        sink = EventSink(queue_size=10)
        return await sink.write_final(failing, kind="run_finished")

    assert asyncio.run(scenario()) is False
    assert len(attempts) == 1


def test_no_final_write_while_the_writer_thread_is_still_wedged_in_the_file():
    """Two threads writing the same stream would corrupt what is already there."""
    release = threading.Event()
    writer = Writer()

    def wedged(_seq: int, _t_ns: int) -> None:
        release.wait(5.0)

    async def scenario():
        sink = EventSink(queue_size=10)
        sink.start()
        sink.offer(wedged, kind="message")
        await asyncio.sleep(0.05)
        left = await sink.drain(timeout=0.1)  # deadline passes, thread still inside
        written = await sink.write_final(writer.emitter("run_finished"), kind="run_finished")
        return left, written

    try:
        _left, written = asyncio.run(scenario())
    finally:
        release.set()

    assert written is False
    assert writer.written == []


# -- shutdown -------------------------------------------------------------------------


def test_drain_reports_what_could_not_be_written():
    def never_reached(_seq: int, _t_ns: int) -> None:
        raise AssertionError("no writer was started")

    async def scenario():
        sink = EventSink(queue_size=10)
        for _ in range(4):
            sink.offer(never_reached, kind="message")
        return await sink.drain(timeout=0.05), sink

    left, sink = asyncio.run(scenario())
    assert left == 4
    assert sink.unwritten == 4


def test_drain_empties_the_queue_when_it_can():
    writer = Writer()

    async def scenario():
        sink = EventSink(queue_size=100)
        for _ in range(50):
            sink.offer(writer.emitter("message"), kind="message")
        sink.start()
        return await sink.drain(timeout=3)

    assert asyncio.run(scenario()) == 0
    assert len(writer.written) == 50


# -- shape ----------------------------------------------------------------------------


def test_offer_is_synchronous_so_the_forwarding_path_cannot_await_it():
    assert not inspect.iscoroutinefunction(EventSink.offer)


def test_the_writer_is_a_daemon_thread_so_a_wedged_write_cannot_hold_up_exit():
    async def scenario():
        sink = EventSink(queue_size=1)
        sink.start()
        thread = sink._thread  # noqa: SLF001 - the structural property is the point
        assert thread is not None
        assert thread.daemon is True
        await sink.drain(timeout=2)

    run(scenario)


def test_a_queue_must_have_room_for_something():
    with pytest.raises(ValueError, match="positive"):
        EventSink(queue_size=0)
