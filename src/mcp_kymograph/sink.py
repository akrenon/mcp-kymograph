"""The queue between observation and the recording file.

The rule this exists to enforce: when observation is slower than the traffic, observation
loses, not the connection.

**The writer is a thread, not a task, and that is the whole point.** Writing is synchronous
— masking, serialising, ``flush`` — and a ``flush`` on a wedged filesystem does not raise,
it simply does not return. On the event loop that stalls every pump with it. Measured
before this was changed: a 500 ms write cost the forwarding path 500 ms. Encapsulation does
not help, because ``try``/``except`` catches exceptions, not failure to return. Only a
separate thread does, and blocking I/O there releases the GIL rather than holding the loop.

**Sequence numbers are assigned on the loop side, on the way in.** A dropped event still
consumes its number, so a gap shows at the jump rather than only as a total at the end. The
number never crosses into the writer thread; the ordering guarantee lives where the ordering
decisions are made.

**Two classes of event.** ``offer`` is for what may be lost — messages and server stderr.
``put`` is for what may not. A non-droppable event waits instead of being dropped, and
waits without blocking the loop.

**One invariant holds the ordering together.** While a non-droppable event waits for room,
``offer`` drops immediately instead of queueing. Without it, a later event overtakes a
waiting earlier one and lands in the file with a higher number first, which makes gap
detection read nonsense. The side effect is deliberate and worth knowing when reading the
counter afterwards: under pressure, a waiting lifecycle event indirectly costs more messages
than the queue length alone would suggest.

Non-droppable events share a single serial gate and take their number *inside* it. Two
waiters would otherwise be woken in an order nothing promises to match the order their
numbers were handed out in.

**Shared state between the loop and the writer thread, in full:**

* ``_dropped`` — events discarded because the queue was full
* ``_stalled`` — whether writing has failed and observation has been shut down
* ``_unwritten`` — events still queued when the drain deadline passed

Three fields, one lock, and this list. If a fourth is ever needed, it belongs here first.
Everything else — the sequence counter, the gate, the waiting count — is touched by the
loop alone.

This module knows nothing about recorders or events. It moves numbered callables, which
keeps it testable against a list.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

#: How many events may wait to be written before the droppable ones start being dropped.
DEFAULT_QUEUE_SIZE = 1000

#: How long shutdown waits for the queue to empty. Generous on purpose: a recording without
#: an ending is a broken recording, and the queue holds work — masking and serialising — not
#: just bytes. What does not make it is reported as unwritten rather than waited for.
DEFAULT_DRAIN_SECONDS = 5.0

#: How long the final write may take before it is abandoned. Short on purpose: it runs after
#: the connection is already over, and a tool that hangs on shutdown is its own failure.
DEFAULT_FINAL_WRITE_SECONDS = 2.0

#: How often a waiting non-droppable event retries, how often the writer looks for work,
#: and how often shutdown checks the writer. Waiting by polling keeps the loop free;
#: lifecycle events are rare enough that the cost is nothing.
DEFAULT_POLL_SECONDS = 0.005


@dataclass(frozen=True, slots=True)
class Pending:
    """One event, numbered and timestamped, waiting to be written."""

    seq: int
    t_ns: int
    kind: str
    emit: Callable[[int, int], None]


class EventSink:
    """A bounded, numbered queue with a single writer thread behind it."""

    def __init__(
        self,
        *,
        queue_size: int = DEFAULT_QUEUE_SIZE,
        clock: Callable[[], int] = time.monotonic_ns,
        on_stall: Callable[[int, str], None] | None = None,
        wait_poll_seconds: float = DEFAULT_POLL_SECONDS,
    ) -> None:
        if queue_size < 1:
            raise ValueError("queue_size must be positive")
        self._queue: queue.Queue[Pending] = queue.Queue(maxsize=queue_size)
        self._clock = clock
        self._origin_ns = clock()
        self._on_stall = on_stall
        self._wait_poll = wait_poll_seconds

        # Loop side only.
        self._gate = asyncio.Lock()
        self._seq = 0
        self._waiting = 0

        # Shared with the writer thread; see the module docstring.
        self._lock = threading.Lock()
        self._dropped = 0
        self._stalled = False
        self._unwritten = 0

        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    # -- state ----------------------------------------------------------------------

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def stalled(self) -> bool:
        with self._lock:
            return self._stalled

    @property
    def unwritten(self) -> int:
        with self._lock:
            return self._unwritten

    @property
    def queued(self) -> int:
        return self._queue.qsize()

    @property
    def assigned(self) -> int:
        """How many sequence numbers have been handed out, written or not."""
        return self._seq

    @property
    def waiting(self) -> int:
        """Non-droppable events currently waiting for room."""
        return self._waiting

    def elapsed_ns(self) -> int:
        return self._clock() - self._origin_ns

    # -- submission -----------------------------------------------------------------

    def offer(self, emit: Callable[[int, int], None], *, kind: str) -> bool:
        """Submit a droppable event. Never waits, never raises; returns whether it queued.

        Called from the forwarding path, so it has no await point at all: there is nowhere
        here for the connection to get stuck.
        """
        if self.stalled:
            return False

        seq = self._next_seq()
        pending = Pending(seq=seq, t_ns=self.elapsed_ns(), kind=kind, emit=emit)

        # The ordering invariant: a waiting non-droppable event must not be overtaken.
        if self._waiting:
            self._count_drop()
            return False
        try:
            self._queue.put_nowait(pending)
        except queue.Full:
            self._count_drop()
            return False
        return True

    async def put(self, emit: Callable[[int, int], None], *, kind: str) -> None:
        """Submit a non-droppable event, waiting for room if there is none."""
        if self.stalled:
            return

        async with self._gate:
            # Inside the gate, so two waiters cannot have their numbers handed out in one
            # order and reach the queue in another.
            pending = Pending(seq=self._next_seq(), t_ns=self.elapsed_ns(), kind=kind, emit=emit)
            self._waiting += 1
            try:
                while True:
                    try:
                        self._queue.put_nowait(pending)
                        return
                    except queue.Full:
                        # Polling rather than blocking: the loop must stay free.
                        await asyncio.sleep(self._wait_poll)
            finally:
                self._waiting -= 1

    async def write_final(
        self,
        emit: Callable[[int, int], None],
        *,
        kind: str,
        timeout: float = DEFAULT_FINAL_WRITE_SECONDS,
    ) -> bool:
        """Write one event directly, bypassing both the queue and the stall.

        This exists for ``run_finished`` alone. A recording that stops without an ending is
        the failure the drain deadline is meant to avoid, so the ending is still attempted
        after writing has failed.

        It runs on its own daemon thread with its own short deadline, for the same reason
        the writer is a thread: a path that ignores the stall can walk straight into what
        caused it, and a blocking write cannot be interrupted. If that thread never returns,
        the process can still exit — which is why it is a daemon and not a pooled worker,
        whose join at exit would put the hang back.

        Refused outright while the writer thread is still alive after its own deadline: that
        thread is wedged inside the file, and a second thread writing to the same stream
        would corrupt what is already there.

        One attempt. No retry, nothing raised upwards. A failure is reported by the caller
        on stderr and changes nothing else, the server's exit code included.
        """
        if self._thread is not None and self._thread.is_alive():
            return False

        pending = Pending(seq=self._next_seq(), t_ns=self.elapsed_ns(), kind=kind, emit=emit)
        loop = asyncio.get_running_loop()
        outcome: asyncio.Future[bool] = loop.create_future()

        def settle(value: bool) -> None:
            if not outcome.done():
                outcome.set_result(value)

        def report(value: bool) -> None:
            # The deadline may already have passed and the loop closed with it. A thread
            # that finally returns then has nobody left to tell, and must not raise on the
            # way out — it is a daemon whose result is no longer wanted.
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(settle, value)

        def attempt() -> None:
            try:
                pending.emit(pending.seq, pending.t_ns)
            except BaseException:
                report(False)
            else:
                report(True)

        threading.Thread(target=attempt, name="mcp-kymograph-final-write", daemon=True).start()

        try:
            return await asyncio.wait_for(asyncio.shield(outcome), timeout)
        except asyncio.TimeoutError:
            return False

    # -- the writer thread ------------------------------------------------------------

    def start(self) -> None:
        """Start the writer thread. Daemon, so a wedged write cannot hold up exit."""
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="mcp-kymograph-writer", daemon=True
            )
            self._thread.start()

    def _run(self) -> None:
        while True:
            try:
                pending = self._queue.get(timeout=DEFAULT_POLL_SECONDS)
            except queue.Empty:
                if self._stopping.is_set():
                    return
                continue
            self._write(pending)

    def _write(self, pending: Pending) -> None:
        if self.stalled:
            return
        try:
            pending.emit(pending.seq, pending.t_ns)
        except Exception:  # noqa: BLE001 - any write failure stops observation, not the run
            self._stall(from_seq=pending.seq, reason="write_failed")

    def stop_observing(self, *, from_seq: int, reason: str) -> None:
        """Shut observation down from the outside, e.g. after an observer error."""
        self._stall(from_seq=from_seq, reason=reason)

    def _stall(self, *, from_seq: int, reason: str) -> None:
        with self._lock:
            if self._stalled:
                return
            self._stalled = True
        # Outside the lock: the callback writes to stderr and may attempt a last event.
        if self._on_stall is not None:
            with contextlib.suppress(Exception):
                self._on_stall(from_seq, reason)

    # -- shutdown -------------------------------------------------------------------

    async def drain(self, timeout: float = DEFAULT_DRAIN_SECONDS) -> int:
        """Let the writer finish what is queued, within a deadline.

        Never an unbounded join: a wedged filesystem must not be able to hold up shutdown
        any more than it may hold up forwarding. Whatever is left is counted and reported.
        """
        self._stopping.set()
        if self._thread is not None:
            deadline = time.monotonic() + timeout
            while self._thread.is_alive() and time.monotonic() < deadline:
                await asyncio.sleep(DEFAULT_POLL_SECONDS)

        leftover = self._queue.qsize()
        with self._lock:
            self._unwritten = leftover
        return leftover

    # -- internals ------------------------------------------------------------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _count_drop(self) -> None:
        with self._lock:
            self._dropped += 1
