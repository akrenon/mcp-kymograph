"""The proxy: the client's process on one side, the real server as a child on the other.

Bytes go through as they arrive, unchanged and without being reassembled. The observer gets
a copy. Nothing on the observing side can hold up the forwarding side — the framer holds no
stream to block on, the sink drops rather than waits, and the writer lives on its own
thread. This module is where that separation is either kept or lost, so it is spelled out
rather than assumed:

* ``Observer.observe`` is synchronous and never raises. An error there ends observation, not
  the connection.
* Every pump is watched centrally. A task whose exception nobody collects disappears
  silently in Python until garbage collection, and the tool would then stand still for no
  visible reason.
* The server closing its stdout is not the server dying. The other direction keeps running,
  and the end-of-file is passed on to the client, because that is what the client would have
  seen without us in the way.

**Shutdown is a single budget, not three deadlines in a row.** Terminating a child that
ignores signals, draining a queue behind a wedged filesystem, and writing the closing event
would otherwise add up to twelve seconds, and a tool that appears hung for twelve seconds is
one nobody waits out. The budget is spent in order, the closing write keeps a reserve, and
what does not fit is reported rather than waited for.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import os
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from functools import partial
from typing import IO, Any

from mcp_kymograph.authorization import Declaration
from mcp_kymograph.engine import Action, Engine, RuleErrorPolicy, RuleFailure
from mcp_kymograph.environment import helper_env, inherited_env
from mcp_kymograph.events import (
    NOT_STARTED,
    STOPPED_BY_SIGNAL,
    STOPPED_BY_STOP_FILE,
    STOPPED_BY_WINDOW,
    Direction,
    Mode,
)
from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES, LineFramer
from mcp_kymograph.guard import Blocked, ClientWriter, GuardedWriter, ScopeGuard
from mcp_kymograph.inspection import MAX_FINDINGS_PER_MESSAGE, NOTHING_SEEN, Inspector
from mcp_kymograph.recorder import Recorder
from mcp_kymograph.sink import DEFAULT_QUEUE_SIZE, EventSink
from mcp_kymograph.verdict import (
    EXIT_INCOMPLETE,
    EXIT_SANDBOX_FAILED,
    EXIT_SERVER_FAILED,
    empty_session,
    server_silent,
)

#: How much is moved per read. Chunks, not lines: reading a line would buffer until the next
#: newline and delay forwarding for as long as a server withholds one.
READ_SIZE = 65536

#: Exit code when a rule wedged the tool and the watchdog had to tear it down. Distinct so a
#: script can tell it apart from any server's own code — nothing else exits with it.
EXIT_RULE_WEDGED = 70

#: A run that is not a result: the sandbox did not hold, so nothing it shows can be trusted
#: as an observation. Its own number (mcp_kymograph.verdict), apart from "data missing" and from
#: "the server never answered", so a batch can tell the three apart.
EXIT_NOT_OBSERVED = EXIT_SANDBOX_FAILED

#: How long to keep reading after the server has exited, so its last words still make it
#: into the recording rather than being lost to the race with process teardown.
TAIL_SECONDS = 0.5

#: How long, by default, the closing event waits for a client half of our own (the driver) to
#: write down how its script ended. It learns of the end the moment its channel closes and
#: needs milliseconds; this bounds the wait if it does not, and is not taken out of the
#: shutdown budget. Without the wait, a script cut off by a server that died under it could
#: lose the race to the closing event, and the recording would not say where its inventory
#: stopped. A wait that runs out is recorded (``limit_exceeded``, ``client_settle_seconds``):
#: under load, a run that lacks its script's end should say why.
CLIENT_SETTLE_SECONDS = 5.0

#: How often the stop file is looked for while a run goes on, besides before each message the
#: client sends on: the kill switch must also stop a run whose client is silent.
STOP_POLL_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class Limits:
    """Everything that bounds a run. Recorded verbatim in ``run_started``."""

    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_duration_seconds: float = 86400.0
    queue_size: int = DEFAULT_QUEUE_SIZE

    #: Time between SIGTERM and SIGKILL for the child's process group.
    terminate_grace_seconds: float = 3.0
    #: Total time shutdown may take, including everything below.
    shutdown_budget_seconds: float = 8.0
    #: Reserved out of the budget so the closing event still has somewhere to go.
    final_write_seconds: float = 2.0
    #: How long a single rule decision may take before the run is considered wedged. A rule
    #: runs synchronously on the event loop, so one that never returns freezes everything at
    #: once — the duration limit, the signal handlers and the shutdown budget all hang off
    #: that same loop. This is the only backstop that still works from outside it.
    rule_budget_seconds: float = 10.0
    #: How long the closing event waits for our own driver to write how its script ended.
    client_settle_seconds: float = CLIENT_SETTLE_SECONDS

    #: What a failing rule costs. ``ABORT`` ends the run, ``CONTINUE`` stills only that one
    #: rule and marks its hits invalid. Not a bound like the others, but run-scoped policy
    #: that belongs in ``run_started`` beside them: a report cannot judge a recording without
    #: knowing which of the two was in force.
    on_rule_error: RuleErrorPolicy = RuleErrorPolicy.ABORT

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_budget_seconds": self.rule_budget_seconds,
            "on_rule_error": self.on_rule_error.value,
            "max_message_bytes": self.max_message_bytes,
            "max_duration_seconds": self.max_duration_seconds,
            "queue_size": self.queue_size,
            "terminate_grace_seconds": self.terminate_grace_seconds,
            "shutdown_budget_seconds": self.shutdown_budget_seconds,
            "client_settle_seconds": self.client_settle_seconds,
        }


@dataclass(frozen=True, slots=True)
class RunOutcome:
    exit_code: int
    reason: str
    message_count: int
    dropped_events: int
    unwritten_events: int
    recording_stopped: bool
    closing_event_written: bool
    quarantined_rules: tuple[str, ...] = ()
    #: What the run observed, per method, and how many values the masker took out of
    #: server-to-client traffic. Carried out so the caller can say it without reading the
    #: recording back.
    observations_by_method: dict[str, int] = field(default_factory=dict)
    findings_by_statement: dict[str, dict[str, int]] = field(default_factory=dict)
    server_redactions: int = 0
    inspection_bounded: int = 0
    #: The sandbox condition that did not hold, or None. Set when the target was never
    #: started, and when its observation turned out untrustworthy afterwards.
    sandbox_failed: str | None = None
    #: ``not_started`` when the server's command could not be started, else None.
    server_failed: str | None = None
    #: What the server wrote to its stdout and the client to us, and whether the server ended
    #: while the client was still connected — as recorded in ``run_finished``.
    server_output_bytes: int = 0
    client_input_bytes: int = 0
    server_exited_first: bool = False
    #: Client messages that were not valid UTF-8: the client's doing, not counted in
    #: ``inspection_bounded``.
    client_undecodable: int = 0
    #: The signal that stopped the run before it ended on its own (``run_stopped``), or None.
    stopped: str | None = None

    @property
    def server_silent(self) -> bool:
        """The server said nothing where it had to (mcp_kymograph.verdict.server_silent). Not
        where the run was stopped first and the server had not ended on its own: whether it
        would have answered is not known."""
        if self.stopped is not None and not self.server_exited_first:
            return False
        return server_silent(
            self.server_output_bytes, self.client_input_bytes, self.server_exited_first
        )

    @property
    def empty_session(self) -> bool:
        """A session took place and nobody said anything (mcp_kymograph.verdict.empty_session)."""
        return (
            self.server_failed is None
            and self.sandbox_failed is None
            and self.stopped is None
            and empty_session(
                self.server_output_bytes, self.client_input_bytes, self.server_exited_first
            )
        )


@dataclass
class Observer:
    """One direction's copy of the traffic, on its way to the recorder.

    Holds no stream and no writer: there is nothing here the connection could wait on.
    """

    sink: EventSink
    recorder: Recorder
    direction: Direction | None
    max_message_bytes: int
    engine: Engine | None = None
    #: Reads the same copy and writes down what the server delivered that a model could read
    #: as instruction. Not a rule: it decides nothing and never touches what is forwarded.
    #: Shared between both directions, because the method a response answers is only known
    #: from the request that went the other way.
    inspector: Inspector | None = None
    #: The corpus entry's name, when the run is one; what the findings are keyed on.
    declared_server: str | None = None
    _framer: LineFramer = field(init=False)
    _disabled: bool = field(init=False, default=False)
    #: Whether the inspector counted the last whole message as bounded; the engine's word on
    #: the same message must not count it a second time.
    _last_bounded: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        self._framer = LineFramer(self.max_message_bytes)

    def note_unreadable(self, outcome) -> None:
        """Count a message the engine could not read as not seen in full, unless the
        inspection counted that very message already. Never raises."""
        if self._disabled or not outcome.unreadable or self.inspector is None:
            return
        if self.direction is not Direction.SERVER_TO_CLIENT:
            # What the client sent is not the server delivering content: the count of messages
            # not seen in full is the server's, and a client's bytes are not held against it.
            return
        if not self._last_bounded:
            self.inspector.count_bounded()
            self._last_bounded = True

    def observe(self, chunk: bytes) -> None:
        """Take a copy of one read. Synchronous, and never raises."""
        if self._disabled:
            return
        try:
            self._submit(self._framer.feed(chunk))
        except Exception:  # noqa: BLE001 - observation may fail; the connection may not
            self._give_up()

    def finish(self) -> None:
        if self._disabled:
            return
        try:
            self._submit(self._framer.finish())
        except Exception:  # noqa: BLE001 - same rule at end of stream
            self._give_up()

    def _submit(self, frames) -> None:
        for frame in frames:
            if self.direction is None:
                emit = partial(
                    self.recorder.server_stderr,
                    raw=frame.data,
                    size_bytes=frame.size_bytes,
                    truncated=frame.truncated,
                )
                kind = "server_stderr"
            else:
                whole = not frame.truncated and not frame.incomplete
                # Let the engine learn request ids from a watched-but-unmodified direction,
                # on this copy, so id-matching works without framing the forwarding path.
                if self.engine is not None and whole:
                    self.engine.observe(self.direction, frame.data)
                # The inspector reads the same copy. A truncated or unfinished frame is not
                # inspected: there is nothing whole to parse, and a signal found in half a
                # message would be an observation about our own framing.
                look = (
                    self.inspector.look(self.direction, frame.data)
                    if self.inspector is not None and whole
                    else NOTHING_SEEN
                )
                self._last_bounded = look.bounded
                emit = partial(
                    self.recorder.message,
                    direction=self.direction,
                    raw=frame.data,
                    size_bytes=frame.size_bytes,
                    truncated=frame.truncated,
                    incomplete=frame.incomplete,
                    responded_method=look.responded_method,
                )
                self.sink.offer(emit, kind="message")
                if look.observations or look.evaluations or look.answered_initialize:
                    # After the message, and pointing back at the number it just took. The
                    # number is read rather than passed because `offer` assigns it inside;
                    # this runs on the loop, which is the only place sequence numbers move.
                    message_seq = self.sink.assigned
                    self._record_name(look, message_seq=message_seq)
                    self._record_observations(look, message_seq=message_seq)
                    self._record_statements(look, message_seq=message_seq)
                continue
            self.sink.offer(emit, kind=kind)

    def _record_observations(self, look, *, message_seq: int) -> None:
        """Offer one event per observation. Droppable, like everything on this path.

        Capped upstream, in the inspector, so a hostile ``tools/list`` cannot turn one
        message into thousands of events and push real traffic out of the queue. The
        uncapped number survives in the run summary.
        """
        for observation in look.observations:
            emit = partial(
                self.recorder.observation,
                direction=self.direction,
                method=look.method,
                message_id=look.message_id,
                message_seq=message_seq,
                surface=observation.surface.value,
                path=observation.path,
                signal=observation.signal.value,
                normalized=observation.normalized,
            )
            self.sink.offer(emit, kind="observation")

    def _record_name(self, look, *, message_seq: int) -> None:
        """A server that names itself other than the corpus entry it runs as. Droppable; the
        announced name also reaches ``run_finished``, on the path that is not."""
        declared = self.declared_server
        if not look.answered_initialize or declared is None or look.announced == declared:
            return
        emit = partial(
            self.recorder.server_name_mismatch,
            declared=declared,
            announced=look.announced,
            message_seq=message_seq,
        )
        self.sink.offer(emit, kind="server_name_mismatch")

    def _record_statements(self, look, *, message_seq: int) -> None:
        """Offer each statement's record for this message, then its findings. Droppable.

        One record per statement that applied, whether or not anything fired, so a statement
        that looked and saw nothing reads differently from one that never looked. The
        findings are capped upstream like observations; the uncapped tally per statement and
        signal reaches ``run_finished``.
        """
        for evaluation in look.evaluations:
            emit = partial(
                self.recorder.statement_evaluated,
                statement=evaluation.statement,
                method=look.method,
                message_id=look.message_id,
                message_seq=message_seq,
                checked=evaluation.checked,
                not_strings=evaluation.not_strings,
                fired={signal.value: count for signal, count in evaluation.fired},
                reason=None if evaluation.reason is None else evaluation.reason.value,
            )
            self.sink.offer(emit, kind="statement_evaluated")
        for finding in look.findings:
            emit = partial(
                self.recorder.finding,
                key=finding.key.to_dict(),
                direction=self.direction,
                method=look.method,
                message_id=look.message_id,
                message_seq=message_seq,
                path=finding.path,
                normalized=finding.normalized,
            )
            self.sink.offer(emit, kind="finding")
        if look.findings_cut:
            # What the cap cut, with the true numbers: a recorded cap, not a gap.
            cut: dict[str, dict[str, int]] = {}
            for statement, signal, count in look.findings_cut:
                cut.setdefault(statement, {})[signal] = count
            emit = partial(
                self.recorder.findings_capped,
                method=look.method,
                message_id=look.message_id,
                message_seq=message_seq,
                cap=MAX_FINDINGS_PER_MESSAGE,
                made=len(look.findings) + sum(n for _, _, n in look.findings_cut),
                recorded=len(look.findings),
                cut=cut,
            )
            self.sink.offer(emit, kind="findings_capped")

    def record_intervention(self, outcome, direction) -> None:
        """Record a change the engine made. Droppable like everything on this path.

        An intervention event rides the observer path and is offered, not awaited: making it
        non-droppable would let a full queue block forwarding, which is the one thing that
        must never happen. Under load a recorded change can therefore be lost, and shows as a
        gap in the sequence numbers like any other drop.
        """
        if self._disabled:
            return
        try:
            emit = partial(
                self.recorder.intervention,
                action=outcome.action.value,
                direction=direction,
                message_id=outcome.message_id,
                original=outcome.original_document,
                replacement=outcome.replacement_document,
                steps=outcome.steps,
            )
            self.sink.offer(emit, kind="intervention")
        except Exception:  # noqa: BLE001 - recording a change may fail; forwarding may not
            self._give_up()

    def record_quarantine(self, failure, direction, message_id, invalidated_hits: int) -> None:
        """Record that a rule was stilled. Droppable, for the same reason as everything here.

        Offered, never awaited: a full queue must not be able to hold up forwarding, and that
        holds for the event that says a rule went bad as much as for any other. What is lost
        here is recovered at the end — the closing event repeats the names of every
        quarantined rule on the one path that does wait.
        """
        if self._disabled:
            return
        try:
            emit = partial(
                self.recorder.rule_quarantined,
                rule=failure.rule,
                reason=failure.reason,
                detail=failure.detail,
                direction=direction,
                message_id=message_id,
                invalidated_hits=invalidated_hits,
            )
            self.sink.offer(emit, kind="rule_quarantined")
        except Exception:  # noqa: BLE001 - recording a quarantine may fail; forwarding may not
            self._give_up()

    def _give_up(self) -> None:
        self._disabled = True
        self.sink.stop_observing(from_seq=self.sink.assigned, reason="observer_error")


def failure_phase(exc: BaseException, caller: str) -> str:
    """The phase a sandbox failure is recorded under: the failure's own, unless the caller
    knows the target has run. After the target nothing can have failed before it, whatever
    default the raising code left in place — and a failure filed as before the target is one
    the server is held not to have caused."""
    if caller == "after_target":
        return caller
    return getattr(exc, "phase", caller)


class Proxy:
    """Runs one session: start the server, connect the streams, shut everything down."""

    def __init__(
        self,
        *,
        argv: Sequence[str],
        recorder: Recorder,
        limits: Limits,
        client_in: IO[bytes],
        client_out: IO[bytes],
        engine: Engine | None = None,
        declaration: Declaration | None = None,
        notice: Callable[[str], None] = lambda message: None,
        mode: Mode = Mode.PROXY,
        script: str | None = None,
        script_digest: str | None = None,
        script_vars: dict[str, str] | None = None,
        statements: Sequence[Any] = (),
        scenario_name: str | None = None,
        server_identity: Any = None,
        server_name: str | None = None,
        reproduction: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        sandbox: Any = None,
        isolation: str = "host",
        cwd: str | os.PathLike[str] | None = None,
        auth: dict[str, Any] | None = None,
        clock: Callable[[], datetime] | None = None,
        guard: ScopeGuard | None = None,
        stop_check: Callable[[], bool] | None = None,
        probe: dict[str, Any] | None = None,
    ) -> None:
        self._argv = list(argv)
        #: The working directory the server's process is started in; None leaves it the one
        #: this process has. It gets no field in the recording.
        self._cwd = cwd
        #: Whether the engagement's stop file is there (mcp_kymograph.engagement.stopped), asked
        #: before each message of the client is passed on and every :data:`STOP_POLL_SECONDS`;
        #: None without an engagement. It stops a passive run too: the kill switch.
        self._stop_check = stop_check
        #: ``run_started.probe``: the module a driven run uses and its options, or None.
        self._probe = probe
        #: The engagement's scope, held against every tool call the client sends before the
        #: server sees it (mcp_kymograph.guard); None: nothing is blocked, as without a file.
        self._guard = guard
        #: The wall clock the closing event reads to say whether the run outlasted its
        #: engagement's window: aware, in UTC. Given by a test to pass the window mid-run.
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))
        #: The runc sandbox (mcp_kymograph.sandbox.runner.Sandbox), or None to run the server as
        #: a child of this process. With one, the server's command line comes from the
        #: sandbox's clearance and from nothing else.
        self._sandbox = sandbox
        self._isolation = isolation
        #: ``run_started.auth``: whom an HTTP run spoke as. None over stdio.
        self._auth = auth
        self._sandbox_failed: str | None = None
        self._sandbox_cleared = False
        self._steps_recorded = 0
        #: Set once the server process exists, or once it is certain it never will. A client
        #: half that speaks before then would spend its first step's time on the sandbox.
        self.launched = asyncio.Event()
        #: Set by a client half of our own once it has written how its script ended; None
        #: when the client is someone else's. The closing event waits for it (bounded).
        self.client_settled: asyncio.Event | None = None
        self._recorder = recorder
        self._limits = limits
        self._engine = engine if engine is not None else Engine()
        # rules_loaded is filled in from the engine we were actually given, not from what the
        # caller declared: it is the one fact in an otherwise unverified record, and a claim
        # about it would be worth nothing.
        base = declaration if declaration is not None else Declaration()
        self._declaration = replace(base, rules_loaded=self._engine.active)
        self._client_in = client_in
        self._client_out = client_out
        self._notice = notice
        # Which half of the conversation we produced. A fact about the run, not a claim about
        # it, so it sits beside `authorization` rather than in it.
        self._mode = mode
        self._script = script
        self._script_digest = script_digest
        self._script_vars = dict(script_vars or {})

        # One inspector for the whole session, shared by both directions: which method a
        # response answers is only knowable from the request that went the other way. It is
        # not a rule and needs no scenario, so it is always there — a run with no scenario
        # observes exactly as much as one with. A scenario's statements only add to it, and
        # its name goes into the key of every finding they make — as does the server's
        # version, established from its own content before the run (mcp_kymograph.identity).
        self._server_identity = server_identity
        self._scenario_name = scenario_name
        self._server_name = server_name
        self._reproduction = reproduction
        self._inputs = inputs
        self._inspector = Inspector(
            statements,
            scenario=scenario_name,
            server_version=None if server_identity is None else server_identity.version,
            server=server_name,
            scrub=recorder.scrub,
        )

        self._sink = EventSink(queue_size=limits.queue_size, on_stall=self._on_stall)
        self._stop = asyncio.Event()
        self._stop_reason: str | None = None
        #: Whether the stop file was seen once. From then on it stops the run whether it is still
        #: there or not: ``--clear`` frees the runs that start after it, not one that has seen it.
        self._stop_file_seen = False
        #: The signal that stopped the run, and the writing of its ``run_stopped``.
        self._stopped_by: str | None = None
        self._stopped_because: str | None = None
        self._stopped_written: asyncio.Task[None] | None = None
        self._stopped_before_target = False
        self._process: asyncio.subprocess.Process | None = None
        self._closing_written = False
        self._watchdog = _RuleWatchdog(limits.rule_budget_seconds, self._on_rule_wedged)
        #: Counted where bytes are forwarded, never where they are recorded.
        self._server_output_bytes = 0
        self._client_input_bytes = 0
        self._server_exited_first = False

    def window_exceeded(self) -> bool | None:
        """Whether the run is closing at or after the end of the window its engagement file
        declares — the moment from which the gate refuses a run (``now >= until``); None
        without a file. Read on every closing path, for ``run_finished``: recorded. A passive run
        (a client's, or a server observed) is not cut short by it; an active one, which this tool
        drives itself, stops before its next step (:meth:`halt_reason`). Nothing judged reads it."""
        until = self._declaration.window_until()
        if until is None:
            return None
        return self._clock() >= until

    def halt_reason(self) -> str | None:
        """Why the run this tool drives itself must not go on, or None: it is already stopping
        (the word of that stop), the stop file is there, or the window has closed — in this
        order. Asked by the driver before each step; a passive run never asks, and is not stopped
        by the window."""
        if self._stop.is_set():
            return self._stop_reason
        if self._stop_file_stops():
            return STOPPED_BY_STOP_FILE
        if self.window_exceeded():
            return STOPPED_BY_WINDOW
        return None

    def stop_run(self, because: str) -> None:
        """Stop the run in order for a reason that is not a signal (``stop_file``,
        ``window_closed``): written down at once, the child ended as at SIGTERM. Does nothing if
        the run is stopping already."""
        self._stop_with(because, because=because)

    def _stop_file_stops(self) -> bool:
        """Whether the stop file is there, or was when last looked; if so the run is stopped for
        it. Once seen it stays True without asking again. A stop for another reason (a signal,
        the window) does not make it True."""
        if self._stop_file_seen:
            return True
        if self._stop_check is None or not self._stop_check():
            return False
        self._stop_file_seen = True
        self._stop_with(STOPPED_BY_STOP_FILE, because=STOPPED_BY_STOP_FILE)
        return True

    async def _watch_stop_file(self) -> None:
        while True:
            if self._stop_file_stops():
                return
            await asyncio.sleep(STOP_POLL_SECONDS)

    async def record_step_skipped(self, *, step: str, reason: str, detail: str = "") -> None:
        """Record a step the driver did not send. The one event a non-client may write here.

        Non-droppable (``put``, not ``offer``), unlike everything on the observer path: an
        absence is only legible while it is written down, and a dropped "this was skipped"
        leaves a recording that looks exactly like one where the step returned nothing. It
        may wait, and waiting is harmless — the caller is the client half, not the forwarding
        path, so a slow queue slows a conversation this tool is having with itself.
        """
        await self._sink.put(
            partial(self._recorder.step_skipped, step=step, reason=reason, detail=detail),
            kind="step_skipped",
        )

    async def record_step_unanswered(
        self, *, step: str, pages: int, reason: str, detail: str = ""
    ) -> None:
        """Record a step that was sent and not answered in full. Non-droppable, like a skip:
        a listing that stopped halfway must not read as all the server has. ``detail`` is the
        TLS library's text under ``tls`` and empty otherwise; the recorder masks it."""
        await self._sink.put(
            partial(
                self._recorder.step_unanswered,
                step=step,
                pages=pages,
                reason=reason,
                detail=detail,
            ),
            kind="step_unanswered",
        )

    async def record_step_called(
        self, *, step: str, tool: str, arguments: Any, check: str | None = None
    ) -> None:
        """Record a tool call that was sent. Non-droppable, like a skip: a call that was made
        and is not in the recording is a conversation nobody can read."""
        await self._sink.put(
            partial(
                self._recorder.step_called, step=step, tool=tool, arguments=arguments, check=check
            ),
            kind="step_called",
        )

    async def record_call_failed(
        self, *, step: str, tool: str, kind: str, code: int | None = None
    ) -> None:
        """Record that a call was answered with an error. Non-droppable."""
        await self._sink.put(
            partial(self._recorder.call_failed, step=step, tool=tool, kind=kind, code=code),
            kind="call_failed",
        )

    async def record_call_blocked(
        self,
        *,
        cause: str,
        where: str,
        tool: str | None = None,
        message_id: str | int | None = None,
        answered: bool = False,
        batch: bool = False,
    ) -> None:
        """Record a tool call the engagement's scope did not allow. Non-droppable: a call that
        was blocked and is not in the recording reads as one that never happened."""
        await self._sink.put(
            partial(
                self._recorder.call_blocked,
                cause=cause,
                where=where,
                tool=tool,
                message_id=message_id,
                answered=answered,
                batch=batch,
            ),
            kind="call_blocked",
        )

    async def _record_blocked(self, blocked: Blocked) -> None:
        await self.record_call_blocked(
            cause=blocked.cause,
            where="proxy",
            tool=blocked.tool,
            message_id=blocked.message_id,
            answered=blocked.answered,
            batch=blocked.batch,
        )

    async def record_script_finished(self, **summary: Any) -> None:
        """Record that the script reached its end, and which. Non-droppable: its absence is
        what marks a script that was cut off, so it must never be absent for another reason."""
        await self._sink.put(
            partial(self._recorder.script_finished, **summary), kind="script_finished"
        )

    async def record_server_failed(self, *, reason: str, detail: str = "") -> None:
        """Record that the server never completed the handshake. Non-droppable, like a skip:
        it is what keeps a run that observed nothing from reading as one that found nothing."""
        await self._sink.put(
            partial(self._recorder.server_failed, reason=reason, detail=detail),
            kind="server_failed",
        )

    async def record_paced(self, *, seconds: float, why: str, status: int | None = None) -> None:
        """Record a wait the driver made in the middle of the run (``why`` ``retry_after``, with
        the ``status`` that asked for it). Non-droppable: a recording that waited and does not
        say so would pass for a run that was quick."""
        await self._sink.put(
            partial(self._recorder.paced, seconds=seconds, why=why, status=status),
            kind="paced",
        )

    @property
    def child_pid(self) -> int | None:
        """The server's process id, so a caller can check nothing was left behind."""
        return None if self._process is None else self._process.pid

    @property
    def ready(self) -> bool:
        """Whether there is a server to talk to, once ``launched`` is set: a driver speaks
        only then. Here that is a child process; a proxy with no child says it another way."""
        return self.child_pid is not None

    # -- the run ----------------------------------------------------------------------

    async def run(self) -> RunOutcome:
        started = time.monotonic_ns()
        self._sink.start()
        await self._sink.put(
            partial(
                self._recorder.run_started,
                argv=self._argv,
                limits=self._limits.as_dict(),
                inputs=self._inputs,
                authorization=self._declaration.as_dict(),
                probe=self._probe,
                mode=self._mode.value,
                script=self._script,
                script_digest=self._script_digest,
                script_vars=self._script_vars,
                server_identity=(
                    None if self._server_identity is None else self._server_identity.to_dict()
                ),
                scenario_name=self._scenario_name,
                server_name=self._server_name,
                reproduction=self._reproduction,
                isolation=self._isolation,
            ),
            kind="run_started",
        )

        for rule_name in self._engine.undeclared_directions():
            # Once per rule, here at the start, because the alternative — warning where the
            # cost is actually paid — would put this in the forwarding path, once per message.
            self._notice(
                f"rule {rule_name} does not declare directions, so it is treated as modifying "
                "both; both directions are forwarded message by message, which is the most "
                "expensive setting. Declare directions to avoid it."
            )

        handlers = self._install_signal_handlers()
        if self._engine.active:
            # Only armed when rules can run: with no scenario there is nothing to wedge.
            self._watchdog.start()
        watcher = asyncio.create_task(self._watch_stop_file(), name="stop-file")
        try:
            argv = await self._launch()
            if argv is None:
                if self._stopped_before_target:
                    return await self._finish_without_server(
                        started, reason="stopped", exit_code=EXIT_INCOMPLETE
                    )
                return await self._finish_without_server(started)
            return await self._session(started, argv)
        finally:
            self.launched.set()
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            self._watchdog.stop()
            self._remove_signal_handlers(handlers)
            await self._kill_process_group(grace=0.0)
            if self._sandbox is not None:
                await asyncio.to_thread(self._sandbox.close)

    # -- the sandbox ------------------------------------------------------------------

    async def _launch(self) -> list[str] | None:
        """The server's command line — with a sandbox, only once the sandbox has been proven.

        Every step of the proof is written down, whether it held or not, on the path that
        cannot drop it. A step that failed, and any error of the sandbox's own, stops the run
        here: no server process is started, and the recording says which condition it was.
        """
        if self._sandbox is None:
            return self._argv
        try:
            cleared = await asyncio.to_thread(self._sandbox.prepare)
        except Exception as exc:  # noqa: BLE001 - every failure of the proof is a failure
            await self._record_sandbox_failure(exc, phase="before_target")
            return None
        await self._record_sandbox_steps()
        if self._stop.is_set():
            # Stopped while the sandbox was being built: the target is not started. The stop is
            # in the recording (run_stopped); the sandbox did not fail, and is not said to.
            self._stopped_before_target = True
            self._notice(f"stopped before the target ({self._stopped_by or self._stop_reason})")
            return None
        self._sandbox_cleared = True
        self._notice(
            f"sandbox held: {len(cleared.conditions)} conditions proven, starting the target"
        )
        return self._sandbox.target_argv(cleared)

    async def _collect_egress(self) -> None:
        """After the target: the kernel's record of what it sent, and the sink held against it."""
        try:
            report = await asyncio.to_thread(self._sandbox.collect)
        except Exception as exc:  # noqa: BLE001 - an account that cannot be had is a failure
            await self._record_sandbox_failure(exc, phase="after_target")
            return
        await self._record_sandbox_steps()
        for attempt in report.attempts:
            await self._sink.put(
                partial(self._recorder.egress_attempt, attempt=attempt), kind="egress_attempt"
            )
        for query in report.dns:
            await self._sink.put(partial(self._recorder.egress_dns, query=query), kind="egress_dns")
        summary = report.summary()
        await self._sink.put(
            partial(self._recorder.egress_summary, summary=summary), kind="egress_summary"
        )
        # Counts only: the destinations and names are the target's choice and stay in the
        # recording, where they are escaped, rather than on a terminal.
        self._notice(
            f"egress: {summary['attempts']} destination(s), {summary['dns_queries']} name(s) "
            "asked"
            + (f", capped {summary['capped']}" if summary["capped"] else "")
            + (
                f", the sink addressed directly {summary['direct_sink_access']} time(s)"
                if summary["direct_sink_access"]
                else ""
            )
        )
        if not report.consistent:
            self._sandbox_failed = "reconciliation"
            self._notice(f"the sink's account differs from the kernel's: {report.problems[0]}")
            await self._sink.put(
                partial(
                    self._recorder.sandbox_failed,
                    condition="reconciliation",
                    phase="after_target",
                    detail={"problems": list(report.problems)},
                ),
                kind="sandbox_failed",
            )

    async def _record_sandbox_steps(self) -> None:
        steps = self._sandbox.steps
        for step in steps[self._steps_recorded :]:
            await self._sink.put(
                partial(
                    self._recorder.sandbox_step,
                    step=step["step"],
                    ok=step["ok"],
                    seconds=step["seconds"],
                    detail=step["detail"],
                ),
                kind="sandbox_step",
            )
        self._steps_recorded = len(steps)

    async def _record_sandbox_failure(self, exc: BaseException, *, phase: str) -> None:
        condition = getattr(exc, "condition", "error")
        detail = getattr(exc, "detail", f"{type(exc).__name__}: {exc}")
        phase = failure_phase(exc, phase)
        self._sandbox_failed = condition
        self._notice(f"sandbox failed ({phase.replace('_', ' ')}): {condition}")
        await self._record_sandbox_steps()
        await self._sink.put(
            partial(self._recorder.sandbox_failed, condition=condition, phase=phase, detail=detail),
            kind="sandbox_failed",
        )

    async def _finish_without_server(
        self, started: int, *, reason: str = "sandbox_failed", exit_code: int = EXIT_NOT_OBSERVED
    ) -> RunOutcome:
        """The closing event of a run whose server was never started: the sandbox did not hold,
        or the command could not be run. There is no server code to hand through, in either
        mode; the exit code is the run's own."""
        self.launched.set()
        budget = _Budget(self._limits.shutdown_budget_seconds, self._limits.final_write_seconds)
        await self._stop_written()
        unwritten = await self._sink.drain(timeout=budget.remaining())
        self._closing_written = await self._sink.write_final(
            partial(
                self._recorder.run_finished,
                reason=reason,
                duration_ns=time.monotonic_ns() - started,
                dropped_events=self._sink.dropped,
                unwritten_events=unwritten,
                findings_by_statement=self._inspector.findings_by_statement,
                server_output_bytes=0,
                client_input_bytes=0,
                server_exited_first=False,
                window_exceeded=self.window_exceeded(),
            ),
            kind="run_finished",
            timeout=self._limits.final_write_seconds,
        )
        return RunOutcome(
            exit_code=exit_code,
            reason=reason,
            message_count=0,
            dropped_events=self._sink.dropped,
            unwritten_events=unwritten,
            recording_stopped=self._sink.stalled,
            closing_event_written=self._closing_written,
            findings_by_statement=self._inspector.findings_by_statement,
            sandbox_failed=self._sandbox_failed,
            server_failed=NOT_STARTED if reason == "server_not_started" else None,
            stopped=self._stopped_by,
        )

    async def _server_not_started(self, started: int, exc: Exception) -> RunOutcome:
        """The command could not be run at all. Written down as the server failing, with what
        the system said — not as a traceback, and not as a run that merely ended early."""
        detail = _not_started(exc, self._cwd, self._argv[0] if self._argv else None)
        self._notice(f"the server could not be started: {detail}")
        await self._sink.put(
            partial(self._recorder.server_failed, reason=NOT_STARTED, detail=detail),
            kind="server_failed",
        )
        return await self._finish_without_server(
            started, reason="server_not_started", exit_code=EXIT_SERVER_FAILED
        )

    # -- the session ------------------------------------------------------------------

    async def _session(self, started: int, argv: list[str]) -> RunOutcome:
        # Inherited for a server we start ourselves (transparency); for a sandboxed one the
        # process is the docker CLI, which must reach the same daemon the sandbox was built
        # on — so it gets the helper environment, like every docker call.
        env = inherited_env() if self._sandbox is None else helper_env()
        if self._cwd is not None and "PWD" in env:
            # As a shell does on cd: a PWD left at the caller's directory would send a server
            # that reads it back to where it was not started.
            env["PWD"] = os.fspath(self._cwd)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                # Its own process group, so termination reaches grandchildren too. A SIGTERM
                # to the child alone leaves whatever it spawned orphaned.
                start_new_session=True,
                cwd=self._cwd,
            )
        except (OSError, ValueError) as exc:
            return await self._server_not_started(started, exc)
        self._process = process
        self.launched.set()

        client_reader = await _reader_for(self._client_in)
        client_writer = await _writer_for(self._client_out)

        to_server = Observer(
            sink=self._sink,
            recorder=self._recorder,
            direction=Direction.CLIENT_TO_SERVER,
            max_message_bytes=self._limits.max_message_bytes,
            engine=self._engine,
            inspector=self._inspector,
            declared_server=self._server_name,
        )
        to_client = Observer(
            sink=self._sink,
            recorder=self._recorder,
            direction=Direction.SERVER_TO_CLIENT,
            max_message_bytes=self._limits.max_message_bytes,
            engine=self._engine,
            inspector=self._inspector,
            declared_server=self._server_name,
        )
        from_stderr = Observer(
            sink=self._sink,
            recorder=self._recorder,
            direction=None,
            max_message_bytes=self._limits.max_message_bytes,
        )

        server_writer: Any = process.stdin
        if self._guard is not None:
            # Everything written to the server, a rule's replacement included, goes through the
            # guard; the client's writer is shared so that its errors never cut a line in two.
            client_writer = ClientWriter(client_writer)
            server_writer = GuardedWriter(
                process.stdin,
                client_writer,
                self._guard,
                limit=self._limits.max_message_bytes,
                record=self._record_blocked,
            )

        pumps = [
            asyncio.create_task(
                self._pump(client_reader, server_writer, to_server, intercept=True),
                name="client-to-server",
            ),
            asyncio.create_task(
                self._pump(process.stdout, client_writer, to_client, intercept=True),
                name="server-to-client",
            ),
            asyncio.create_task(
                self._pump(process.stderr, None, from_stderr, echo=True), name="server-stderr"
            ),
        ]
        timer = asyncio.create_task(self._duration_limit(), name="duration-limit")

        reason = await self._supervise(process, pumps, client_pump=pumps[0])

        # Let the pumps finish what is already in the pipes before tearing them down, or the
        # server's last words are lost to the race with its own exit.
        await asyncio.wait(pumps, timeout=TAIL_SECONDS)
        for task in (*pumps, timer):
            task.cancel()
        await asyncio.gather(*pumps, timer, return_exceptions=True)

        outcome = await self._shut_down(process, reason=reason, started=started)
        _release_pipes(process)
        return outcome

    async def _supervise(
        self,
        process: asyncio.subprocess.Process,
        pumps: list[asyncio.Task[None]],
        *,
        client_pump: asyncio.Task[None],
    ) -> str:
        """Wait for whatever ends the run, collecting every task's outcome centrally."""
        exited = asyncio.create_task(process.wait(), name="server-wait")
        stopped = asyncio.create_task(self._stop.wait(), name="stop-requested")
        extra: list[asyncio.Task[Any]] = []
        watch: set[asyncio.Task[Any]] = {exited, stopped, *pumps}
        reason: str | None = None

        try:
            while watch and reason is None:
                done, watch = await asyncio.wait(watch, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if task is exited:
                        reason = "server_exited"
                        # Ended while the client could still speak: not a reaction to the
                        # client's end of input.
                        self._server_exited_first = not client_pump.done()
                    elif task is stopped:
                        reason = self._stop_reason or "stopped"
                    elif task in pumps:
                        # A pump ending on end-of-file is normal and not the end of the run:
                        # a server may close stdout and keep reading. An exception is fatal,
                        # and is collected here rather than left to vanish unretrieved.
                        error = task.exception()
                        if error is not None:
                            self._notice(f"forwarding failed: {type(error).__name__}")
                            reason = "pump_error"
                        elif task is client_pump:
                            # The client has gone and the server's stdin is closed. Most
                            # servers exit on that by themselves; one that does not must not
                            # outlive the session, and waiting for it forever would hang us.
                            waiter = asyncio.create_task(
                                self._grace_then_stop(), name="client-gone-grace"
                            )
                            extra.append(waiter)
                            watch.add(waiter)
                    # anything else in `watch` is one of ours and needs no verdict
        finally:
            for task in (exited, stopped, *extra):
                if not task.done():
                    task.cancel()
            await asyncio.gather(exited, stopped, *extra, return_exceptions=True)

        return reason or "streams_closed"

    async def _grace_then_stop(self) -> None:
        await asyncio.sleep(self._limits.terminate_grace_seconds)
        self._request_stop("client_eof")
        await asyncio.sleep(3600)  # kept alive until cancelled, so it never counts as done

    # -- pumps ------------------------------------------------------------------------

    async def _pump(
        self,
        reader: Any,
        writer: Any,
        observer: Observer,
        *,
        echo: bool = False,
        intercept: bool = False,
    ) -> None:
        """Move bytes one way and hand a copy to the observer.

        Two paths. Without an active engine — an empty or absent scenario — this is plain
        forwarding: raw chunks straight through, byte for byte, backpressure intact. With an
        active engine and a real direction, forwarding becomes message-by-message, because a
        message cannot be replaced or dropped until it is whole. The observer sees the
        original bytes either way, so the recording is the same faithful log in both.
        """
        if reader is None:
            return
        intercepting = (
            intercept and writer is not None and self._engine.modifies(observer.direction)
        )
        framer = _ForwardFramer(self._limits.max_message_bytes) if intercepting else None
        try:
            while True:
                chunk = await reader.read(READ_SIZE)
                if not chunk:
                    break
                if observer.direction is Direction.CLIENT_TO_SERVER and self._stop_file_stops():
                    # The kill switch, before anything of the client's goes on to the server.
                    break
                if observer.direction is Direction.SERVER_TO_CLIENT:
                    self._server_output_bytes += len(chunk)
                elif observer.direction is Direction.CLIENT_TO_SERVER:
                    self._client_input_bytes += len(chunk)
                if intercepting:
                    await self._forward_intercepted(chunk, framer, writer, observer)
                    continue
                if writer is not None:
                    writer.write(chunk)
                    await writer.drain()  # where backpressure arrives
                if echo:
                    # The server's stderr goes to ours, never into the protocol channel.
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.buffer.flush()
                observer.observe(chunk)
        finally:
            # A stopped run passes nothing more of the client's on: the server still runs, and
            # would read an unfinished line at end-of-file. The end-of-file itself goes on.
            stopped = observer.direction is Direction.CLIENT_TO_SERVER and (
                self._stop.is_set() or self._stop_file_stops()
            )
            if framer is not None:
                for _kind, data in framer.finish():
                    observer.observe(data)
                    if stopped:
                        continue
                    with contextlib.suppress(Exception):
                        writer.write(data)
                        await writer.drain()
            observer.finish()
            if writer is not None:
                settle = getattr(writer, "settle", None)
                if settle is not None:
                    # The guard's last line, and what it blocked, before the end is passed on.
                    with contextlib.suppress(Exception):
                        await settle(stopped=True) if stopped else await settle()
                # Pass the end-of-file on: without us, the other side would have seen it.
                with contextlib.suppress(Exception):
                    writer.close()

    async def _forward_intercepted(
        self, chunk: bytes, framer: _ForwardFramer, writer: Any, observer: Observer
    ) -> None:
        """The message-by-message path. The observer always sees the original bytes."""
        for kind, data in framer.feed(chunk):
            if kind != "message":
                # Overflow spill or an unfinished tail: forwarded verbatim, never decided on.
                # Fed to the observer as-is, so the recording matches one made without a
                # scenario over the same original traffic.
                observer.observe(data)
                writer.write(data)
                await writer.drain()
                continue

            original = data + b"\n"
            observer.observe(original)
            self._watchdog.entering()
            try:
                outcome = self._engine.decide(observer.direction, data)
            except RuleFailure as failure:
                # One rule failed, and it named itself. Whatever the policy, the untouched
                # original goes out: nothing invalid may leave, and the connection must not
                # be corrupted by a bug on our side.
                writer.write(original)
                await writer.drain()
                self._after_rule_failure(failure, observer)
                continue
            except Exception:  # noqa: BLE001 - the engine itself may fail; the connection may not
                # Not a rule but the engine around it. There is no single rule to still, so
                # there is nothing for the continue policy to act on and the run ends — the
                # abort path, regardless of the setting.
                self._notice("the engine failed; forwarding original and ending the run")
                writer.write(original)
                await writer.drain()
                self._request_stop("engine_error")
                continue
            finally:
                self._watchdog.leaving()

            observer.note_unreadable(outcome)
            if outcome.action is Action.DROP:
                observer.record_intervention(outcome, observer.direction)
                continue
            if outcome.action is Action.REPLACE:
                writer.write(outcome.replacement + b"\n")
                await writer.drain()
                observer.record_intervention(outcome, observer.direction)
                continue
            writer.write(original)
            await writer.drain()
            if outcome.steps:
                # Rules took part and changed nothing. Recorded all the same: a scenario that
                # matched and never landed must not read like one that never matched.
                observer.record_intervention(outcome, observer.direction)

    def _after_rule_failure(self, failure: RuleFailure, observer: Observer) -> None:
        """Apply the rule-error policy. Synchronous: this sits in the forwarding path.

        ``ABORT`` ends the run, which is the older behaviour and stays the default: a run
        whose scenario half ran is harder to reason about than one that stopped.

        ``CONTINUE`` stills that rule alone. Interception is *not* switched off — the other
        rules keep working — and the rule's hits are marked invalid rather than deleted: the
        recording stays a verbatim log of what happened, and the judgement about it is a
        separate statement laid beside it.
        """
        if self._limits.on_rule_error is RuleErrorPolicy.ABORT:
            self._notice(f"rule {failure.rule} {failure.detail}; forwarding original, ending run")
            self._request_stop(failure.reason)
            return

        if not self._engine.quarantine(failure.rule):
            return  # already stilled; a second failure from it cannot happen, but say it once
        hits = self._engine.hits(failure.rule)
        self._notice(
            f"rule {failure.rule} {failure.detail}; stilled for the rest of the run. "
            f"Its {hits} recorded hit(s) are invalid. Other rules continue."
        )
        observer.record_quarantine(
            failure,
            observer.direction,
            failure.message_id,
            invalidated_hits=hits,
        )

    async def _duration_limit(self) -> None:
        await asyncio.sleep(self._limits.max_duration_seconds)
        await self._sink.put(
            partial(
                self._recorder.limit_exceeded,
                limit="max_duration",
                value=self._limits.max_duration_seconds,
                unit="seconds",
            ),
            kind="limit_exceeded",
        )
        self._request_stop("duration_limit")

    # -- shutdown ---------------------------------------------------------------------

    async def _shut_down(
        self, process: asyncio.subprocess.Process, *, reason: str, started: int
    ) -> RunOutcome:
        budget = _Budget(self._limits.shutdown_budget_seconds, self._limits.final_write_seconds)

        await self._kill_process_group(
            grace=min(self._limits.terminate_grace_seconds, budget.remaining())
        )
        exit_code, killed_by = _exit_status(process)
        await self._sink.put(
            partial(self._recorder.server_exited, exit_code=exit_code, signal=killed_by),
            kind="server_exited",
        )

        if self._sandbox_cleared:
            # Observation, not shutdown: bounded by the sandbox's own timeouts, and not taken
            # out of the time the recording has to be written in.
            paused = time.monotonic()
            await self._collect_egress()
            budget.extend(time.monotonic() - paused)

        if self.client_settled is not None:
            # Our own client half writes how its script ended before the closing event, not
            # after it, where nothing is read. Bounded, and outside the budget like the above.
            paused = time.monotonic()
            settle = self._limits.client_settle_seconds
            try:
                await asyncio.wait_for(self.client_settled.wait(), settle)
            except asyncio.TimeoutError:
                # The closing event goes on without it, and the recording says it stopped
                # waiting — so a script's end that is missing is not missing without a reason.
                self._notice(f"the driver had not settled after {settle:g} s; closing without it")
                await self._sink.put(
                    partial(
                        self._recorder.limit_exceeded,
                        limit="client_settle_seconds",
                        value=settle,
                        unit="seconds",
                    ),
                    kind="limit_exceeded",
                )
            budget.extend(time.monotonic() - paused)

        await self._stop_written()
        unwritten = await self._sink.drain(timeout=budget.remaining())

        self._closing_written = await self._sink.write_final(
            partial(
                self._recorder.run_finished,
                reason=reason,
                duration_ns=time.monotonic_ns() - started,
                dropped_events=self._sink.dropped,
                unwritten_events=unwritten,
                quarantined_rules=self._engine.quarantined,
                observations_by_method=self._inspector.observations_by_method,
                findings_by_statement=self._inspector.findings_by_statement,
                inspection_bounded=self._inspector.bounded_messages,
                announced_server=self._inspector.announced_server,
                server_output_bytes=self._server_output_bytes,
                client_input_bytes=self._client_input_bytes,
                server_exited_first=self._server_exited_first,
                client_undecodable=self._inspector.client_undecodable,
                window_exceeded=self.window_exceeded(),
            ),
            kind="run_finished",
            timeout=self._limits.final_write_seconds,
        )
        if not self._closing_written:
            self._notice("the recording has no closing event: the final write did not succeed")

        silent = server_silent(
            self._server_output_bytes, self._client_input_bytes, self._server_exited_first
        ) and (self._stopped_by is None or self._server_exited_first)
        return RunOutcome(
            # A run that observed nothing exits with its own state, in either mode; only a
            # server that was observed has its own code handed through.
            exit_code=(
                EXIT_NOT_OBSERVED
                if self._sandbox_failed is not None
                else EXIT_SERVER_FAILED
                if silent
                else _reported_exit_code(exit_code, killed_by)
            ),
            reason=reason,
            message_count=self._recorder.message_count,
            dropped_events=self._sink.dropped,
            unwritten_events=unwritten,
            recording_stopped=self._sink.stalled,
            closing_event_written=self._closing_written,
            quarantined_rules=self._engine.quarantined,
            observations_by_method=self._inspector.observations_by_method,
            findings_by_statement=self._inspector.findings_by_statement,
            server_redactions=self._recorder.server_redactions,
            inspection_bounded=self._inspector.bounded_messages,
            sandbox_failed=self._sandbox_failed,
            server_output_bytes=self._server_output_bytes,
            client_input_bytes=self._client_input_bytes,
            server_exited_first=self._server_exited_first,
            client_undecodable=self._inspector.client_undecodable,
            stopped=self._stopped_by,
        )

    async def _kill_process_group(self, *, grace: float) -> None:
        """Terminate the child's whole group, politely first, then not."""
        process = self._process
        if process is None or process.returncode is not None:
            return
        try:
            group = os.getpgid(process.pid)
        except ProcessLookupError:
            return

        with contextlib.suppress(ProcessLookupError):
            os.killpg(group, signal.SIGTERM)
        if grace > 0:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(process.wait()), grace)
                return

        with contextlib.suppress(ProcessLookupError):
            os.killpg(group, signal.SIGKILL)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(process.wait()), 1.0)

    # -- signals and stalls -------------------------------------------------------------

    def _install_signal_handlers(self) -> list[int]:
        loop = asyncio.get_running_loop()
        installed = []
        for number in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(number, self._on_signal, number)
            except (NotImplementedError, ValueError, RuntimeError):
                continue
            installed.append(number)
        return installed

    def _remove_signal_handlers(self, numbers: list[int]) -> None:
        loop = asyncio.get_running_loop()
        for number in numbers:
            with contextlib.suppress(NotImplementedError, ValueError, RuntimeError):
                loop.remove_signal_handler(number)

    def _request_stop(self, reason: str) -> None:
        if self._stop_reason is None:
            self._stop_reason = reason
        self._stop.set()

    def _on_signal(self, number: int) -> None:
        """SIGINT or SIGTERM: whoever runs this tool stops the run. Written down at once
        (``run_stopped``), before the stop has any consequence — the server killed, the
        sandbox left unbuilt — so the recording shows those as the stop's and not as failures
        of their own (mcp_kymograph.verdict)."""
        self._stop_with(signal.Signals(number).name, because=STOPPED_BY_SIGNAL)

    def _stop_with(self, name: str, *, because: str) -> None:
        """Write down that the run is stopped (``run_stopped``: ``name`` is the signal's, or the
        word of the other reasons) and ask for the stop. The first stop is the run's; a later one
        changes nothing."""
        if self._stopped_by is None:
            self._stopped_by = name
            self._stopped_because = because
            self._stopped_written = asyncio.ensure_future(
                self._sink.put(
                    partial(self._recorder.run_stopped, signal=name, because=because),
                    kind="run_stopped",
                )
            )
        self._request_stop(because)

    async def _stop_written(self) -> None:
        """``run_stopped`` reaches the queue before the closing event does."""
        if self._stopped_written is not None:
            await asyncio.gather(self._stopped_written, return_exceptions=True)

    def _on_rule_wedged(self, elapsed: float) -> None:
        """Runs on the watchdog thread while the event loop is stuck inside a rule.

        Nothing here may touch the loop — it is not running. It writes straight to the real
        stderr, takes the child's process group down so nothing is orphaned, and ends the
        process. The recording keeps everything written up to this point (each event is
        flushed as it happens) but has no closing event, which is the honest record of a run
        that was killed rather than finished.
        """
        message = (
            f"kymograph: a rule has not returned after {elapsed:.1f}s; the tool is wedged. "
            "Killing the server and aborting. Rules must not block.\n"
        )
        with contextlib.suppress(Exception):
            sys.stderr.write(message)
            sys.stderr.flush()

        process = self._process
        if process is not None:
            with contextlib.suppress(Exception):
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)

        os._exit(EXIT_RULE_WEDGED)

    def _on_stall(self, from_seq: int, reason: str) -> None:
        """Called on the writer thread once writing has failed.

        The notice comes first, because it is the part that can still be delivered. The
        event is then attempted once — into the same file that just refused a write, so it
        may well fail, and that failure changes nothing.

        It carries the number of the event that could not be written. That number is the
        first one missing, so the event occupies it rather than taking a new one, which also
        keeps sequence assignment on the loop side where it belongs.
        """
        self._notice(f"recording stopped ({reason}); forwarding continues")
        with contextlib.suppress(Exception):
            self._recorder.recording_stopped(
                from_seq, self._sink.elapsed_ns(), reason=reason, from_seq=from_seq
            )


class _RuleWatchdog:
    """Notices a rule that never returns, from a thread the wedged loop cannot stop.

    A rule is called synchronously on the event loop. That is the design — a decision that
    needed to wait would be a design error — but it means a rule that blocks takes every
    safety mechanism with it: the duration limit, the signal handlers and the shutdown budget
    all live on that same loop, and none of them can fire. Measured: a blocking rule left the
    tool unresponsive to SIGINT and SIGTERM and orphaned the server process.

    So the backstop lives outside the loop. It cannot rescue the run — a wedged thread cannot
    be interrupted in Python — but it turns a silent hang with an orphaned child into a loud
    abort that takes the child down with it.
    """

    #: How often the watchdog looks. Coarse on purpose: it is a backstop, not a timer.
    TICK_SECONDS = 0.25

    def __init__(self, budget: float, on_wedged: Callable[[float], None]) -> None:
        self._budget = budget
        self._on_wedged = on_wedged
        self._started_at: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="mcp-kymograph-rule-watchdog", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None

    def entering(self) -> None:
        self._started_at = time.monotonic()

    def leaving(self) -> None:
        self._started_at = None

    def _run(self) -> None:
        while not self._stop.wait(self.TICK_SECONDS):
            started = self._started_at
            if started is None:
                continue
            elapsed = time.monotonic() - started
            if elapsed >= self._budget:
                self._on_wedged(elapsed)
                return


class _ForwardFramer:
    """Splits the forwarding stream into messages, for the decision point.

    Unlike the observer's :class:`LineFramer`, this one must never *lose* bytes: a message
    too large to hold is forwarded raw rather than dropped, because forwarding is the
    guarantee. It yields ``("message", line)`` for a complete line that can be decided on,
    and ``("raw", bytes)`` for anything that must go through verbatim — the spill of an
    oversized message, or an unfinished tail at end of stream. The buffer never grows past
    the limit: once a line would exceed it, what is held is spilled as raw and the rest of
    that line streams through until its newline.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._buf = bytearray()
        self._overflow = False

    def feed(self, chunk: bytes) -> list[tuple[str, bytes]]:
        out: list[tuple[str, bytes]] = []
        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            if newline == -1:
                self._absorb(chunk, start, len(chunk), out)
                return out
            if self._overflow:
                out.append(("raw", chunk[start : newline + 1]))
                self._overflow = False
                self._buf.clear()
            elif len(self._buf) + (newline - start) > self._limit:
                # A complete line, but too big to hold: spill and stream it raw.
                if self._buf:
                    out.append(("raw", bytes(self._buf)))
                    self._buf.clear()
                out.append(("raw", chunk[start : newline + 1]))
            else:
                self._buf += chunk[start:newline]
                out.append(("message", bytes(self._buf)))
                self._buf.clear()
            start = newline + 1

    def _absorb(self, chunk: bytes, start: int, end: int, out: list[tuple[str, bytes]]) -> None:
        if end <= start:
            return
        if self._overflow:
            out.append(("raw", chunk[start:end]))
            return
        if len(self._buf) + (end - start) > self._limit:
            if self._buf:
                out.append(("raw", bytes(self._buf)))
                self._buf.clear()
            out.append(("raw", chunk[start:end]))
            self._overflow = True
            return
        self._buf += chunk[start:end]

    def finish(self) -> list[tuple[str, bytes]]:
        if self._overflow:
            self._overflow = False
            return []
        if self._buf:
            tail = bytes(self._buf)
            self._buf.clear()
            return [("raw", tail)]
        return []


class _Budget:
    """A single shutdown allowance, spent in order, with the closing write kept back."""

    def __init__(self, total: float, reserved: float) -> None:
        self._deadline = time.monotonic() + max(total - reserved, 0.0)

    def remaining(self) -> float:
        return max(self._deadline - time.monotonic(), 0.0)

    def extend(self, seconds: float) -> None:
        """Give back time spent on something that is not shutdown."""
        self._deadline += max(seconds, 0.0)


def _exit_status(process: asyncio.subprocess.Process) -> tuple[int | None, int | None]:
    code = process.returncode
    if code is None:
        return None, None
    if code < 0:
        return None, -code
    return code, None


#: What a failed start means, in our words. The command itself is in ``run_started.argv``,
#: masked; it is not repeated here.
_NOT_STARTED = {
    errno.ENOENT: "the command was not found",
    errno.EACCES: "the command is not executable (permission denied)",
    errno.EPERM: "the command may not be executed",
    errno.ENOEXEC: "the command is not in a format the system can execute",
    errno.ENOTDIR: "a part of the command's path is not a directory",
}


def _not_started(
    exc: Exception, cwd: str | os.PathLike[str] | None = None, program: str | None = None
) -> str:
    """Why the server's command could not be started, without its path or arguments.

    With a working directory given, a failure to enter it is said as that: the system reports
    it with the same numbers as a command that is missing or may not be run, and names the
    directory as the file concerned. A command whose program is that very directory is the
    command's failure.
    """
    number = getattr(exc, "errno", None)
    concerned = getattr(exc, "filename", None)
    if (
        cwd is not None
        and concerned is not None
        and os.fspath(concerned) == os.fspath(cwd)
        and program != os.fspath(cwd)
    ):
        code = errno.errorcode.get(number, type(exc).__name__)
        return f"the working directory could not be entered ({code})"
    if number in _NOT_STARTED:
        return f"{_NOT_STARTED[number]} ({errno.errorcode[number]})"
    if isinstance(number, int) and number in errno.errorcode:
        return f"the command could not be started ({errno.errorcode[number]})"
    return f"the command could not be started ({type(exc).__name__})"


def _reported_exit_code(exit_code: int | None, killed_by: int | None) -> int:
    if exit_code is not None:
        return exit_code
    if killed_by is not None:
        return 128 + killed_by  # the shell convention for death by signal
    return 1


def _release_pipes(process: asyncio.subprocess.Process) -> None:
    """Close the child's pipe transports rather than leaving them to the collector.

    Left alone they are closed during garbage collection, which may happen after the event
    loop is gone; the resulting noise would sit in the way of a real problem later.
    """
    for stream in (process.stdin,):
        if stream is not None:
            with contextlib.suppress(Exception):
                stream.close()
    transport = getattr(process, "_transport", None)
    if transport is not None:
        with contextlib.suppress(Exception):
            transport.close()


def _is_streamable(binary: IO[bytes]) -> bool:
    """Whether asyncio can put a pipe transport on this descriptor.

    Only pipes, sockets and character devices qualify. A client normally hands us pipes, but
    a redirection to a regular file is a perfectly ordinary way to run the tool, and it must
    not fail with a transport error that reads like a protocol problem.
    """
    try:
        mode = os.fstat(binary.fileno()).st_mode
    except (OSError, ValueError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISCHR(mode)


class _FileReader:
    """A reader for a regular file. Reads there return immediately or hit end-of-file."""

    def __init__(self, binary: IO[bytes]) -> None:
        self._binary = binary

    async def read(self, size: int) -> bytes:
        return self._binary.read(size)


class _FileWriter:
    """A writer for a regular file, where there is no backpressure to arrive."""

    def __init__(self, binary: IO[bytes]) -> None:
        self._binary = binary

    def write(self, data: bytes) -> None:
        self._binary.write(data)

    async def drain(self) -> None:
        self._binary.flush()

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._binary.flush()


async def _reader_for(binary: IO[bytes]) -> Any:
    if not _is_streamable(binary):
        return _FileReader(binary)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), binary)
    return reader


async def _writer_for(binary: IO[bytes]) -> Any:
    if not _is_streamable(binary):
        return _FileWriter(binary)
    loop = asyncio.get_running_loop()
    # FlowControlMixin is the protocol asyncio itself uses for pipe writers; without it the
    # writer has no drain, and without drain there is no backpressure.
    transport, protocol = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, binary)
    return asyncio.StreamWriter(transport, protocol, None, loop)
