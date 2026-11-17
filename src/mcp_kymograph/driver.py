"""The driver mode: Kymograph is the client as well as the man in the middle.

In proxy mode a real client starts this tool and this tool starts the server. In driver mode
there is no foreign client: the operator starts the tool, the tool starts the server, and the
client half of the conversation is produced here, from a fixed script. No model, no sampling,
no decisions taken from what the server said beyond the one thing that has to be read — which
capabilities it offered.

**The proxy is not bypassed, it is fed.** The driver writes into a pipe that is the proxy's
client side and reads from another that is the proxy's client output. Everything downstream —
framing, the observer, the masker, the inspector, the engine, the shutdown budget — is the
same code on the same path as in proxy mode, so a driven recording is a recording in exactly
the same sense and the same format. Nothing here writes a message event; it only speaks, and
the proxy records what was said, as it would for anyone else.

**Turn by turn, never in a block.** A request is sent only once the previous answer has come
back. Sending the script's lines all at once produces a perfectly valid recording of a
*different* conversation — every request ahead of every answer — and the interleaving that a
real session shows would be gone (the lesson pinned in ``tests/test_handshake.py``).

**A step that was not sent is recorded as a step that was not sent.** Never as an empty
result: "the server offers no prompts" and "the server has no prompts" are different
statements, and a report that cannot tell them apart is worse than one that says neither.
That is what :class:`mcp_kymograph.events.StepSkipped` is for, and it is written on the
non-droppable path, because an absence that got dropped reads as nothing at all. A step that
was sent and never answered in full says so too (:class:`mcp_kymograph.events.StepUnanswered`),
and the script's end is written down as evidence (:class:`mcp_kymograph.events.ScriptFinished`):
a script that was cut off writes no end, and its run is then never read as a full inventory.

**The opening is the era detection, where there is one.** A driver given an :class:`Opening` sends
``server/discover`` first and lets :class:`mcp_kymograph.eras.Detector` read what comes back: a
server of the modern era (2026-07-28) is then spoken to without a handshake, every request
carrying ``params._meta``; a legacy one gets ``initialize``, in the version the opening names; a
server that requires what this tool does not offer, or speaks no version it knows, ends the run
as ``server_failed`` with reason ``protocol_unsupported`` and no listing sent. Every decision is
written down (:class:`mcp_kymograph.events.EraDecided`). Without an opening the driver asks
``initialize`` for 2025-06-18, as it always did; that is stdio without an engagement. In the modern
era a listing whose response stream broke is asked for once more, with a new id
(:class:`mcp_kymograph.events.StepReissued`); a tool call is not, because it acts.

**The built-in ``discovery`` script does not act.** It lists; it reads no resource and calls no
tool. Discovery on a system someone else operates must not have side effects, and a call whose
result depends on the world would take the determinism with it.

**A script file may act, and then it is a scenario in the eyes of the gate.** Besides the
listings it may hold ``call`` steps (:class:`CallStep`, ``tools/call`` with a name and
arguments), at most a few, each sent only when the server offered ``tools`` *and* a
``tools/list`` of the same script delivered that tool — a script does not call what the server
did not say it has. A call is a side effect on a system, so a script with at least one needs
what a scenario needs against a target outside localhost: the operator's confirmation that an
engagement covers it (:mod:`mcp_kymograph.authorization`). A call is recorded when it is sent
(:class:`mcp_kymograph.events.StepCalled`), an error answer to it is recorded and the script goes
on (:class:`mcp_kymograph.events.CallFailed`), and what the server returns is read by the same
inspector as everything else: this module decides nothing from the answer.

**An active run ends when it is told to.** Before each step, and before each request a probe
module makes, the driver asks whether the run may go on (``halt``): a signal to the process, the
engagement's stop file or the end of the engagement's window says no. Then no further step is
sent, each step that was not says so (:data:`~mcp_kymograph.events.RUN_HALTED`), the script's end
is written, and the proxy ends the server as it does at SIGTERM (``run_stopped``). A client that is
someone else's is not the driver's to stop at the window's end.

**A probe module is a script that decides as it goes** (:mod:`mcp_kymograph.probes`). It is given a
context, never the channel: each request it makes is held against the window, the stop file and
its ``max_calls``, and a call goes through :meth:`Driver._call` and so past the scope guard.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import IO, Any

from mcp_kymograph import __version__, eras, events
from mcp_kymograph.events import (  # noqa: F401 - re-exported: the driver's own words
    BLOCKED_BY_DRIVER,
    CALL_RPC_ERROR,
    CALL_TOOL_ERROR,
    CLOSED,
    CURSOR_INVALID,
    DRIVER_ERROR,
    HTTP_SSE_ONLY,
    HTTP_STATUS,
    HTTP_UNREACHABLE,
    INVENTORY_CAPPED,
    INVENTORY_COMPLETE,
    INVENTORY_NONE,
    INVENTORY_PARTIAL,
    MALFORMED_CAPABILITY,
    MAX_READ_DEPTH,
    NO_ANSWER,
    NO_HANDSHAKE,
    NOT_OFFERED,
    OBSERVATION_REJECTED,
    PAGE_LIMIT,
    PARTIAL_REASONS,
    PROBE_CALLS_EXHAUSTED,
    PROTOCOL_UNSUPPORTED,
    RATE_LIMITED,
    RUN_HALTED,
    SESSION_LOST,
    STOPPED_BECAUSE,
    STREAM_BROKEN,
    TLS,
    TOOL_NOT_LISTED,
    UNAUTHORIZED,
    UNREADABLE,
    load_bytes,
)
from mcp_kymograph.framing import DEFAULT_MAX_MESSAGE_BYTES
from mcp_kymograph.guard import ScopeGuard
from mcp_kymograph.probes.base import CallResult, Probe, ProbeEnded
from mcp_kymograph.proxy import Proxy, RunOutcome

#: The protocol version the driver announces. A fixed string, not a negotiation: the server
#: answers with the version it will speak, and that answer is in the recording.
PROTOCOL_VERSION = "2025-06-18"

#: How many pages of a paginated listing are followed before the driver stops asking. A
#: server that keeps handing out cursors must not be able to make a run unbounded. Reaching
#: it is recorded, so a truncated listing cannot read as a complete one.
MAX_PAGES = 20

#: How long one step waits for its answer before the script gives up. Per step, not per run:
#: the run's own bound is ``--max-duration``, which is far too coarse to tell "this server is
#: slow" from "this server never answered".
DEFAULT_STEP_TIMEOUT = 30.0

#: The clock a step's remaining time is read from, and the sleep of the one wait a rate limit may
#: cost a step. Module-level so that a test moves both without waiting (as ``pacing`` does).
_monotonic = time.monotonic
_sleep = asyncio.sleep

#: The least a step may be given. The first step's wait includes the server's own start, and
#: under runc the start of its container: measured for the project's own Python server
#: (2026-10-06, ten runs each), the first answer took 32–42 ms on the host and 373–411 ms under
#: runc, and with all eight cores busy 42–93 ms and 586–889 ms; every later step at most 9 ms.
#: The floor is about twice the worst of these, so that the floor itself never turns a correct
#: server into one that failed. Below it, the setting decides the outcome, not the server — an
#: input error.
MIN_STEP_TIMEOUT = 2.0

#: How many messages the driver will read past while waiting for one answer. A server that
#: talks endlessly without ever answering must not be able to hold a step open forever within
#: its timeout.
MAX_INTERLEAVED = 1000

#: The longest line the driver reads, the same as the proxy's message limit: a line the proxy
#: records whole, the driver can read. A longer one is read past, never held, and counts as a
#: line the driver could not read (:data:`~mcp_kymograph.events.UNREADABLE`).
MAX_LINE_BYTES = DEFAULT_MAX_MESSAGE_BYTES

#: The least the driver reads, whatever the message limit: asyncio's own default, and so what
#: the driver read before it took a limit at all. A message limit below it bounds what the
#: proxy records whole, never which answers the driver can read.
MIN_LINE_BYTES = 64 * 1024

#: The largest error code recorded as a number. Codes are small integers; anything beyond is
#: the server's noise and is recorded as no code at all. (Spelled in ``events``, which the
#: recorder reads too.)
MAX_CODE = events.MAX_RPC_CODE

#: What :meth:`ClientChannel.read_line` returns for a line it read past without holding it.
#: Never a line otherwise: every line it returns has at least its newline or one byte.
OVERSIZED = b""


#: The reasons with which the detection stops that make a run ``protocol_unsupported``: the server
#: requires what this tool does not offer, or speaks no version it knows. The others
#: (``handshake_*``) are failures of the handshake as the driver has always named them.
UNSUPPORTED_STOPS = frozenset(
    {
        eras.MODERN_REFUSED,
        eras.NO_COMMON_VERSION,
        eras.UNKNOWN_VERSION,
        eras.MALFORMED_VERSION,
    }
)

#: The most capability names and versions a stop keeps for the terminal's line.
MAX_NAMED = eras.MAX_VERSIONS


@dataclass(frozen=True, slots=True)
class Opening:
    """How a driver opens a conversation with the era detection (``eras``): over which transport,
    for which legacy version it asks ``initialize`` where it has a choice, and the generation the
    engagement file names for the target, if it does (``{"era": …, "version": …}``, the version
    optional). The declared generation is compared with the detected one and recorded; it is never
    a reason to stop."""

    transport: str = eras.TRANSPORT_HTTP
    request_version: str = eras.LEGACY_REQUEST_VERSION
    declared: dict[str, Any] | None = None


class OversizedTimeout(asyncio.TimeoutError):
    """The time ran out while a line over the limit was being read past.

    A timeout like any other, and also more than one: something came, and it could not be
    read. The driver names the step's cause for that, not for the silence.
    """


@dataclass(frozen=True, slots=True)
class Step:
    """One discovery call, and what the server has to have offered for it to be sent."""

    method: str
    #: The capability key that must appear in the server's ``initialize`` answer. A listing
    #: the server never said it has is not asked for — asking anyway produces a "method not
    #: found" error that reads, in a recording, exactly like a broken server.
    requires: str
    #: Whether to follow ``nextCursor`` until the listing is exhausted or :data:`MAX_PAGES`.
    paginate: bool = False


@dataclass(frozen=True, slots=True)
class CallStep:
    """One tool call of a script file, and what the server has to have offered for it.

    Sent only if ``tools`` was offered and a ``tools/list`` earlier in the same script
    delivered ``tool``. ``arguments`` are final: placeholders were replaced when the file was
    read. ``check`` is the path the script names for the answer, kept as text for the
    recording. ``timeout`` replaces the run's step timeout for this call alone.
    """

    tool: str
    arguments: dict[str, Any]
    check: str | None = None
    timeout: float | None = None

    @property
    def method(self) -> str:
        return "tools/call"

    @property
    def requires(self) -> str:
        return "tools"


@dataclass(frozen=True, slots=True)
class Script:
    """A fixed conversation. Named, because the name goes into the recording.

    ``capabilities`` is what the driver honestly offers, which is nothing: it implements no
    sampling, no roots and no elicitation. Announcing one would invite the server to send a
    request that would never be answered, and the resulting silence would be our doing and
    look like the server's.

    ``steps`` are what follows the handshake, which every script has and which is not a step.
    ``digest`` and ``variables`` belong to a script read from a file (mcp_kymograph.script): the
    SHA-256 of its bytes and the values set for its placeholders. The built-in script has
    neither.
    """

    name: str
    protocol_version: str
    client_info: dict[str, Any]
    capabilities: dict[str, Any]
    steps: tuple[Step | CallStep, ...]
    digest: str | None = None
    variables: dict[str, str] = field(default_factory=dict)

    @property
    def acts(self) -> bool:
        """Whether the script calls a tool. Such a script is a scenario for the gate."""
        return any(isinstance(step, CallStep) for step in self.steps)


DISCOVERY = Script(
    name="discovery",
    protocol_version=PROTOCOL_VERSION,
    client_info={"name": "mcp-kymograph", "version": __version__},
    capabilities={},
    steps=(
        Step("tools/list", requires="tools", paginate=True),
        Step("resources/list", requires="resources", paginate=True),
        Step("resources/templates/list", requires="resources", paginate=True),
        Step("prompts/list", requires="prompts", paginate=True),
    ),
)

#: The built-in scripts. A fixed table, like ``SCENARIOS``; a script file is read by
#: mcp_kymograph.script and is not entered here.
SCRIPTS: dict[str, Script] = {DISCOVERY.name: DISCOVERY}


# -- why a step was not sent, or not answered: the vocabulary lives with the events -------


class ClientChannel:
    """Two pipes standing in for a client's stdin and stdout.

    Real pipes rather than an in-memory shortcut, so the proxy reads and writes over exactly
    the transport it would use for any other client — the same framing, the same
    backpressure, the same end-of-file. A shortcut here would make a driven recording
    something subtly other than a recorded session.
    """

    def __init__(self, max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self._max_line_bytes = max_line_bytes
        to_proxy_read, to_proxy_write = os.pipe()
        from_proxy_read, from_proxy_write = os.pipe()
        #: Handed to the proxy as its client side.
        self.proxy_in: IO[bytes] = os.fdopen(to_proxy_read, "rb", buffering=0)
        self.proxy_out: IO[bytes] = os.fdopen(from_proxy_write, "wb", buffering=0)
        self._our_out: IO[bytes] = os.fdopen(to_proxy_write, "wb", buffering=0)
        self._our_in: IO[bytes] = os.fdopen(from_proxy_read, "rb", buffering=0)
        self._reader: asyncio.StreamReader | None = None
        self._read_transport: asyncio.BaseTransport | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._write_closed = False

    async def open(self) -> None:
        loop = asyncio.get_running_loop()
        self._reader = asyncio.StreamReader(limit=self._max_line_bytes)
        self._read_transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(self._reader), self._our_in
        )
        transport, protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, self._our_out
        )
        self._writer = asyncio.StreamWriter(transport, protocol, None, loop)

    async def send(self, line: bytes) -> None:
        if self._writer is None or self._write_closed:
            raise ConnectionError("the client channel is closed")
        self._writer.write(line)
        await self._writer.drain()

    async def read_line(self, timeout: float) -> bytes | None:
        """One line, :data:`OVERSIZED` for one longer than this channel's limit, or None at
        end of stream. Raises :class:`asyncio.TimeoutError` on time — :class:`OversizedTimeout`
        if it ran out while a line over the limit was being read past.

        A line over the limit is read past to its end and dropped as it goes, never held: a
        server decides how long its lines are. If the time runs out while it is read past, the
        stream is left inside that line, and the channel must not be read from again — which
        the driver does not: a step that timed out ends the script.
        """
        if self._reader is None:
            return None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout  # one time for the line, however it is read
        try:
            return await asyncio.wait_for(self._reader.readuntil(b"\n"), timeout)
        except asyncio.IncompleteReadError as end:
            return end.partial or None  # the last line, without its newline, or the end
        except asyncio.LimitOverrunError as overrun:
            try:
                remaining = max(deadline - loop.time(), 0.0)
                await asyncio.wait_for(self._read_past(overrun.consumed), remaining)
            except asyncio.TimeoutError:
                raise OversizedTimeout from None
            return OVERSIZED

    async def _read_past(self, held: int) -> None:
        """Drop the rest of a line that is over the limit, ``held`` bytes of it buffered."""
        assert self._reader is not None  # noqa: S101 - only called after a read
        while True:
            await self._reader.readexactly(held)
            try:
                await self._reader.readuntil(b"\n")
                return
            except asyncio.IncompleteReadError:
                return
            except asyncio.LimitOverrunError as overrun:
                held = overrun.consumed

    def close_write(self) -> None:
        """End of input for the server: what a client does when it is finished.

        This is the whole shutdown handshake for stdio. There is no ``shutdown`` method in
        the protocol; the transport closing *is* the goodbye, and the proxy turns it into a
        polite termination of the child with the budget it already has.
        """
        if self._write_closed:
            return
        self._write_closed = True
        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
        else:  # never opened; close the raw handle so the proxy still sees the end
            with contextlib.suppress(Exception):
                self._our_out.close()

    def close(self) -> None:
        self.close_write()
        # The read side closes itself at the end of the stream; after a timeout it never saw
        # one, so it is closed here as well.
        if self._read_transport is not None:
            with contextlib.suppress(Exception):
                self._read_transport.close()
        for handle in (self._our_in, self.proxy_in, self.proxy_out):
            with contextlib.suppress(Exception):
                handle.close()


@dataclass
class DriveOutcome:
    """What the script did. The recording is the record; this is for the closing line."""

    sent: tuple[str, ...] = ()
    skipped: tuple[tuple[str, str], ...] = ()
    protocol_version: str | None = None
    capabilities: tuple[str, ...] = ()
    #: Why the handshake did not complete (``no_answer``, ``answer_unreadable``,
    #: ``connection_closed``, ``handshake_incomplete``, and over HTTP the channel's words), or
    #: None. Set, the run observed nothing the script asks about and is not a result.
    server_failed: str | None = None
    #: The ``detail`` written with it: our own sentence, or under ``tls`` the TLS library's text
    #: as the channel gave it — filtered and cut, not masked — for the terminal to show through
    #: ``display``. Empty when the handshake completed.
    server_failed_detail: str = ""
    #: Steps sent and not answered in full: ``(step, pages answered, reason, detail)``. The
    #: detail is empty for every reason but ``tls``, where it is the TLS library's text as the
    #: channel gave it — filtered and cut, not masked — as ``server_failed_detail`` is. The
    #: recording's ``script_finished`` has the first three only; the detail is in the step's
    #: ``step_unanswered``, masked.
    unanswered: tuple[tuple[str, int, str, str], ...] = ()
    #: How the script ended (``INVENTORY_*``); None if it never got to say.
    inventory: str | None = None
    #: The tools whose call was sent, and those whose call came back as an error.
    called: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    #: The generation spoken (``legacy`` or ``modern``), None if the opening never got that far.
    era: str | None = None
    #: A detection that stopped with ``protocol_unsupported``, for the terminal's line: ``reason``
    #: (the detector's), ``code`` (the error's, or None), ``required`` (the capabilities the
    #: server requires), ``versions`` (those it names) and ``version`` (the one it answered
    #: ``initialize`` with). All of it the server's, whole; the terminal masks and displays it.
    stop: dict[str, Any] | None = None
    #: Whether the generation the engagement file names for the target is another than the
    #: detected one (or, if it names a version, than the version): None without a declaration.
    declared_differs: bool | None = None
    declared: dict[str, Any] | None = None
    #: The cause the scope guard gave for a call it did not send, and the tool's name (cut), or
    #: None. Set, the gate missed a call it had to catch: a mistake of this tool, and the run ended
    #: there (``driver_error`` for the steps not sent).
    blocked: tuple[str, str] | None = None
    #: Why the run was told to stop before the script or module was done (``signal``,
    #: ``stop_file``, ``window_closed``, …), or None.
    halted: str | None = None
    #: Under a token observation, each exchange as the server answered it (``role``, ``method``,
    #: ``accepted``, ``http_status``, ``rpc_code``), and what the token's expiry was (``expiry``,
    #: for the kind ``expired``). Empty and None otherwise. The terminal prints one line each.
    exchanges: tuple[dict[str, Any], ...] = ()
    expiry: str | None = None


#: The step a probe module that failed is recorded as not having finished.
PROBE_STEP = Step("probe", requires="")


def probe_script(probe: Probe) -> Script:
    """The script a probe module's run is recorded under: the handshake of every script, and no
    steps of its own — the module makes its requests as it goes."""
    return Script(
        name=f"probe:{probe.name}",
        protocol_version=PROTOCOL_VERSION,
        client_info={"name": "mcp-kymograph", "version": __version__},
        capabilities={},
        steps=(),
    )


class Driver:
    """Speaks one script into the channel, one turn at a time."""

    def __init__(
        self,
        script: Script,
        channel: ClientChannel,
        *,
        record_skipped: Any,
        record_failed: Any = None,
        record_unanswered: Any = None,
        record_finished: Any = None,
        record_called: Any = None,
        record_call_failed: Any = None,
        record_era: Any = None,
        record_reissued: Any = None,
        record_paced: Any = None,
        record_blocked: Any = None,
        record_observation: Any = None,
        observation: str | None = None,
        is_literal: Callable[[int], bool] | None = None,
        expiry: Callable[[], str | None] | None = None,
        guard: ScopeGuard | None = None,
        halt: Callable[[], str | None] | None = None,
        stop: Callable[[str], None] | None = None,
        probe: Probe | None = None,
        probe_options: Mapping[str, str] | None = None,
        opening: Opening | None = None,
        notice: Any = lambda message: None,
        step_timeout: float = DEFAULT_STEP_TIMEOUT,
    ) -> None:
        self._script = script
        self._channel = channel
        self._opening = opening
        self._record_era = record_era
        self._record_reissued = record_reissued
        #: Called with ``seconds``, ``why`` and ``status`` for the wait a 429 or 503 cost.
        self._record_paced = record_paced
        #: The second wall behind the gate: the engagement's tool rules, held against each call
        #: just before it is sent (mcp_kymograph.guard). None without an engagement, and for one
        #: with no rule about tools.
        self._guard = guard
        self._record_blocked = record_blocked
        #: A token observation (``events.TOKEN_OBSERVATIONS``) or None. Under one, every exchange
        #: is noted as the server answered it, and a 401 or 403 is the result: the run ends there
        #: without a failure (:data:`OBSERVATION_REJECTED`). ``expiry`` is asked at the end of the
        #: run and says what the kind ``expired`` records of the token's expiry.
        self._record_observation = record_observation
        self._observation = observation
        #: Whether a number may not be written as a code: it holds a literal of the run (a token
        #: of digits) in its decimal form, or it is a known value (``recorder.wire_code``).
        self._is_literal = is_literal
        self._expiry = expiry
        self._exchanges: list[dict[str, Any]] = []
        self._rejected = False
        self._blocked: tuple[str, str] | None = None
        #: Asked before each step: why the run must not go on, or None (``Proxy.halt_reason``).
        #: And what is called to stop it when that is news (``Proxy.stop_run``). None for a
        #: driver whose run nobody stops.
        self._halt = halt
        self._stop_run = stop
        self._halted: str | None = None
        #: The probe module this run is for, with its options; the script then has no steps.
        self._probe = probe
        self._probe_options = dict(probe_options or {})
        #: The generation spoken, once the opening has settled it, and the ``_meta`` every
        #: modern request carries.
        self._era: str | None = None
        self._meta: dict[str, Any] | None = None
        self._stop: dict[str, Any] | None = None
        self._record_called = record_called
        self._record_call_failed = record_call_failed
        #: Tools a ``tools/list`` of this script has delivered, and the calls made and failed.
        self._listed: set[str] = set()
        self._called: list[str] = []
        self._failed: list[str] = []
        self._record_skipped = record_skipped
        self._record_failed = record_failed
        self._record_unanswered = record_unanswered
        self._record_finished = record_finished
        self._server_failed: str | None = None
        self._server_failed_detail = ""
        #: Why the last request came back without an answer: ``no_answer``,
        #: ``answer_unreadable`` or ``connection_closed``, or the channel's word for it. And
        #: under ``tls`` the channel's text, which goes into the step's ``detail``.
        self._failure = NO_ANSWER
        self._failure_detail = ""
        self._unanswered: list[tuple[str, int, str, str]] = []
        self._notice = notice
        # Seconds a step may wait for its answer, in all: not per line read meanwhile.
        self._timeout = step_timeout
        self._next_id = 1
        self._sent: list[str] = []
        self._skipped: list[tuple[str, str]] = []
        self.outcome = DriveOutcome()

    async def run(self) -> DriveOutcome:
        """Drive the whole script. Never raises: a bug here must not cost the recording.

        The channel is closed on every path out, because the proxy ends its run on the
        client's end-of-file and nothing else. A driver that failed without closing would
        leave the tool waiting for a client that is no longer speaking.
        """
        try:
            await self._channel.open()
            await self._converse()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - the client half failing is not the run
            self._notice(f"the driver failed ({type(exc).__name__}); the recording stands")
            await self._skip_remaining(self._script.steps or (PROBE_STEP,), DRIVER_ERROR)
        inventory = self._inventory()
        expiry = self._expiry() if self._expiry is not None else None
        try:
            if self._observation is not None and self._record_observation is not None:
                await self._record_observation(
                    kind=self._observation, exchanges=tuple(self._exchanges), expiry=expiry
                )
            # Written before the channel closes, so it is in the queue ahead of anything the
            # end of the conversation sets off. A script that is cancelled never gets here,
            # and that absence is what marks it.
            if self._record_finished is not None:
                await self._record_finished(
                    inventory=inventory,
                    sent=tuple(self._sent),
                    skipped=tuple(self._skipped),
                    # Without the detail: unmasked, it belongs to the terminal, not here.
                    unanswered=tuple(item[:3] for item in self._unanswered),
                    called=tuple(self._called),
                    failed=tuple(self._failed),
                    era=self._era,
                    protocol_version=self.outcome.protocol_version,
                )
        finally:
            try:
                # A channel over HTTP ends its session before it closes; stdio has no goodbye.
                goodbye = getattr(self._channel, "goodbye", None)
                if goodbye is not None:
                    with contextlib.suppress(Exception):
                        await goodbye(self._timeout)
            finally:
                self._channel.close_write()
        self.outcome = DriveOutcome(
            sent=tuple(self._sent),
            skipped=tuple(self._skipped),
            protocol_version=self.outcome.protocol_version,
            capabilities=self.outcome.capabilities,
            server_failed=self._server_failed,
            server_failed_detail=self._server_failed_detail,
            unanswered=tuple(self._unanswered),
            inventory=inventory,
            called=tuple(self._called),
            failed=tuple(self._failed),
            era=self._era,
            stop=self._stop,
            declared_differs=self.outcome.declared_differs,
            declared=self.outcome.declared,
            blocked=self._blocked,
            halted=self._halted,
            exchanges=tuple(self._exchanges),
            expiry=expiry,
        )
        return self.outcome

    def _inventory(self) -> str:
        """How far the script got, in one word, from what it recorded on its way."""
        if self._server_failed is not None:
            return INVENTORY_NONE
        if self._halted is not None:
            return INVENTORY_PARTIAL
        if self._rejected:
            # The server turned the observation away: what it offers was not asked for, or not
            # to the end. Nothing is known when it did not let the opening through.
            return INVENTORY_NONE if self._era is None else INVENTORY_PARTIAL
        if self._unanswered or any(reason in PARTIAL_REASONS for _, reason in self._skipped):
            return INVENTORY_PARTIAL
        if any(reason == PAGE_LIMIT for _, reason in self._skipped):
            return INVENTORY_CAPPED
        return INVENTORY_COMPLETE

    # -- the conversation ------------------------------------------------------------

    def _halt_reason(self) -> str | None:
        """Why the run must not go on, or None. Only the reasons of :data:`STOPPED_BECAUSE` halt
        the driver (a signal, the stop file, the end of the window). The first time one is news the
        proxy is told to stop (a no-op when the stop is the proxy's own, as a signal is); after
        that the answer is the same, and no step is sent. Any other stop of the proxy (the
        duration limit, a scenario rule) is not the driver's to act on: the steps go on being
        sent and the run ends as it did before there was a halt, by what the channel says."""
        if self._halted is None and self._halt is not None:
            reason = self._halt()
            if reason in STOPPED_BECAUSE:
                self._halted = reason
                if self._stop_run is not None:
                    self._stop_run(reason)
                self._notice(f"the run is stopped ({reason}): no further step is sent")
        return self._halted

    async def _converse(self) -> None:
        if self._halt_reason() is not None:
            await self._skip_remaining(self._script.steps or (PROBE_STEP,), RUN_HALTED)
            return
        if self._opening is None:
            handshake = await self._initialize()
            if handshake is None:
                return
            capabilities = handshake.get("capabilities")
            if not isinstance(capabilities, dict):
                capabilities = {}
            self._era = eras.ERA_LEGACY
            self.outcome = DriveOutcome(
                protocol_version=_text_or_none(handshake.get("protocolVersion")),
                capabilities=tuple(sorted(str(key) for key in capabilities)),
                era=self._era,
            )
            # Sent straight after the answer and before anything else: the protocol requires
            # it, and it draws no answer of its own, so there is nothing to wait for.
            await self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            self._sent.append("notifications/initialized")
        else:
            capabilities = await self._open()
            if capabilities is None:
                return

        if self._probe is not None:
            await self._run_probe(self._probe, capabilities)
            return

        for index, step in enumerate(self._script.steps):
            if self._halt_reason() is not None:
                await self._skip_remaining(self._script.steps[index:], RUN_HALTED)
                return
            reason = _why_not(step, capabilities)
            if reason is None and isinstance(step, CallStep) and step.tool not in self._listed:
                reason = TOOL_NOT_LISTED
            if reason is not None:
                await self._skip(step.method, reason)
                continue
            if isinstance(step, CallStep):
                answered = await self._call(step)
            else:
                answered = await self._listing(step)
            if not answered:
                # No answer, or the channel went away: the rest of the script is not sent,
                # and each remaining step says so rather than being left out.
                await self._skip_remaining(self._script.steps[index + 1 :], self._failure)
                return

    async def _run_probe(self, probe: Probe, capabilities: dict[str, Any]) -> None:
        """The module's run, after the handshake, through a context. It ends when the module
        does or when the context ends it (:class:`ProbeEnded`, already recorded as a step that
        was not sent); a module that raises anything else is a mistake of ours, recorded as such."""
        context = _ProbeContext(self, probe, capabilities)
        try:
            await probe.run(context, self._probe_options)
        except ProbeEnded:
            if self._rejected:
                # The observation was turned away in the module's run: the rest of what it would
                # have sent is not sent, and says so (rule 14 reads the reason).
                await self._skip(
                    PROBE_STEP.method,
                    OBSERVATION_REJECTED,
                    detail="the server rejected the token; the rest of the module was not sent",
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a module failing is not the run
            self._notice(
                f"the probe {probe.name} failed ({type(exc).__name__}); the recording stands"
            )
            await self._skip(PROBE_STEP.method, DRIVER_ERROR)

    async def _initialize(self) -> dict[str, Any] | None:
        """The handshake. Its answer is the only thing the script reads and acts on."""
        answer = await self._request(
            "initialize",
            {
                "protocolVersion": self._script.protocol_version,
                "capabilities": self._script.capabilities,
                "clientInfo": self._script.client_info,
            },
        )
        if answer is None:
            await self._not_opened()
            return None
        self._sent.append("initialize")
        result = answer.get("result")
        if not isinstance(result, dict):
            await self._no_handshake()
            return None
        return result

    async def _not_opened(self, what: str = "initialize") -> None:
        """The opening got no answer: the channel's reason (or the silence, or the server's side
        closing) is the run's, and every step says it was not sent. ``what`` is the message that
        went unanswered."""
        # The probe's step stands in for a script without steps for a halt, and for a token
        # observation the server turned away, where the module is the one thing not sent and says
        # so: any other cause leaves a probe run's opening with the steps it always had, none.
        halted = self._failure == RUN_HALTED
        stands_in = halted or self._rejected
        steps = (self._script.steps or (PROBE_STEP,)) if stands_in else self._script.steps
        await self._skip_remaining(steps, self._failure)
        if halted:
            return  # stopped, not failed: the server said nothing wrong
        if self._rejected:
            return  # the result of an observation, not a failure of the server (rule 14)
        detail = {
            NO_ANSWER: f"{what} was not answered",
            UNREADABLE: f"{what} was not answered in a line the driver could read",
            HTTP_STATUS: f"{what} was answered with an HTTP status that carries no answer",
            SESSION_LOST: f"the server refused the session before {what} was answered",
            HTTP_UNREACHABLE: "the HTTP endpoint could not be reached, or closed the "
            "connection before it answered",
            HTTP_SSE_ONLY: "the endpoint speaks only the deprecated HTTP+SSE transport",
            UNAUTHORIZED: f"the endpoint answered {what} with 401 or 403: it did not "
            "accept the credentials this run sent, or none was sent",
            STREAM_BROKEN: "the response stream broke before the answer came, and was not "
            "resumed to it",
            RATE_LIMITED: f"the endpoint answered {what} with 429 or 503 and would not take it "
            "again after the one wait this run makes, or asked for longer than the step had left",
        }.get(self._failure, f"the server's side closed before {what} was answered")
        if self._failure == TLS:
            detail = self._failure_detail  # the library's text: which check failed, and how
        await self._fail(self._failure, detail)

    async def _no_handshake(self) -> None:
        """An error answer to ``initialize``, or one shaped in a way nothing can be read out of.
        Either way nothing is known about what the server offers, so nothing is asked for."""
        await self._skip_remaining(self._script.steps, NO_HANDSHAKE)
        await self._fail(NO_HANDSHAKE, "initialize was answered without a result")

    # -- the opening with the era detection ---------------------------------------------

    async def _open(self) -> dict[str, Any] | None:
        """Open as the era detection says: the probe, then ``initialize`` or nothing. The
        capabilities the server offered, or None when the run stops here (and says why)."""
        opening = self._opening
        assert opening is not None  # noqa: S101 - only called with one
        detector = eras.Detector(
            self._script.client_info,
            self._script.capabilities,
            first_id=self._next_id,
            request_version=opening.request_version,
            transport=opening.transport,
        )
        step = detector.start()
        while True:
            self._next_id = max(self._next_id, step.identifier + 1)
            probing = step.message["method"] == eras.PROBE_METHOD
            answer = await self._transact(step.message, lenient=probing)
            if answer is None:
                fed = self._unanswered_opening(probing)
                if fed is None:
                    await self._not_opened(step.message["method"])
                    return None
            else:
                self._sent.append(step.message["method"])
                # A modern error to the probe may come with a null id (the body of a 400): it is
                # read as the answer to the probe, and only here.
                fed = {**answer, "id": step.identifier} if probing else answer
            reply = detector.answer(fed)
            if isinstance(reply, eras.Send):
                step = reply
                continue
            return await self._decided(reply)

    def _unanswered_opening(self, probing: bool) -> str | None:
        """What to feed the detector for an opening message that drew no answer, or None when the
        run is over without it: a probe that never reached the endpoint (``tls``,
        ``http_unreachable``, ``unauthorized``, ``rate_limited``) says nothing about the era, and
        ``initialize`` has no answer to read at all — its failure is the channel's, as ever. A halt
        after a wait feeds the detector nothing either, in the probe or in ``initialize``: it is
        the run's, and no ``era_decided`` is written."""
        failure = self._failure
        if failure == RUN_HALTED:
            return None  # the server was not asked again: it has no say in how this ended
        if not probing:
            return eras.NO_ANSWER if failure == NO_ANSWER else eras.CLOSED
        if failure in (TLS, HTTP_UNREACHABLE, UNAUTHORIZED, RATE_LIMITED, OBSERVATION_REJECTED):
            return None
        if failure == NO_ANSWER:
            return eras.NO_ANSWER
        if failure == CLOSED and self._opening.transport == eras.TRANSPORT_STDIO:
            return eras.CLOSED
        # Over HTTP an answer that is no JSON-RPC message — another status, an empty or broken
        # body, a stream that ended — and over stdio a line the driver could not read.
        return eras.NOT_JSON_RPC

    async def _decided(self, detection: eras.Detection) -> dict[str, Any] | None:
        """Write down how the detection ended and act on it. The capabilities when it proceeds."""
        declared = self._opening.declared
        differs = _differs(declared, detection)
        await self._record_decision(detection, declared, differs)
        self.outcome = DriveOutcome(declared=declared, declared_differs=differs)
        if detection.action == eras.PROCEED:
            self._era = detection.era
            capabilities = detection.capabilities
            self.outcome = DriveOutcome(
                protocol_version=detection.version,
                capabilities=tuple(sorted(str(key) for key in capabilities)),
                era=self._era,
                declared=declared,
                declared_differs=differs,
            )
            if self._era == eras.ERA_MODERN:
                self._meta = eras.meta(self._script.client_info, self._script.capabilities)
            else:
                for message in detection.followup:
                    # The protocol requires it straight after the answer; it draws no answer.
                    await self._send(message)
                    self._sent.append(message["method"])
            return capabilities
        reason = detection.reason
        if reason in UNSUPPORTED_STOPS:
            self._era = detection.era
            self._stop = _stop_facts(detection)
            await self._skip_remaining(self._script.steps, PROTOCOL_UNSUPPORTED)
            await self._fail(PROTOCOL_UNSUPPORTED, _stop_words(detection))
        elif reason in (eras.HANDSHAKE_REFUSED, eras.NO_RESULT):
            await self._no_handshake()
        else:
            # Unanswered, closed: the channel's reason, said as it always was; a server that
            # closed on the probe never saw ``initialize``, and the detail names the probe.
            await self._not_opened(
                eras.PROBE_METHOD if reason == eras.CLOSED_ON_PROBE else "initialize"
            )
        return None

    async def _record_decision(
        self, detection: eras.Detection, declared: dict[str, Any] | None, differs: bool | None
    ) -> None:
        if self._record_era is None:
            return
        probe = detection.probe
        await self._record_era(
            era=detection.era,
            version=detection.version,
            outcome=detection.action,
            reason=detection.reason,
            probe=None
            if probe is None
            else {"outcome": probe.outcome, "code": probe.code, "supported": probe.supported},
            exchanges=detection.exchanges,
            refusal=detection.error,
            declared=declared,
            differs=differs,
            observations=detection.observations,
        )

    async def _fail(self, reason: str, detail: str) -> None:
        """The server did not get as far as the handshake: say so as the run's result, not
        only as steps that were skipped — a run that observed nothing is not a clean one."""
        self._server_failed = reason
        self._server_failed_detail = detail
        if self._record_failed is not None:
            await self._record_failed(reason=reason, detail=detail)

    async def _listing(
        self, step: Step, before_request: Callable[[str], Awaitable[None]] | None = None
    ) -> bool:
        """One listing, following cursors. False when an answer never came — and then the
        step says how many pages it did get, so a partial listing is never a short one. A
        cursor that cannot be sent back is recorded the same way, but the answer came: True.

        Every page after the first and every request made again is held against the end of the
        run first: if the run must stop, the step says so (``run_halted``, with the pages it did
        get), the listing is not complete, and True is returned — the answers came, and the next
        check stops the run. ``before_request``, if given, is awaited with the method before each
        of those requests (a probe module's context counts them against its ``max_calls``)."""
        cursor: str | None = None
        for page in range(MAX_PAGES):
            if page > 0 and not await self._may_ask(step, page, before_request):
                return True
            params = {"cursor": cursor} if cursor is not None else None
            answer = await self._request(step.method, params)
            if answer is None and self._reissue_wanted():
                # A listing asks nothing of the world, so it may be asked for again; a call may
                # not (see ``_call``).
                if not await self._may_ask(step, page, before_request):
                    return True
                await self._reissued(step.method, page)
                answer = await self._request(step.method, params)
            if answer is None:
                if page == 0 and self._failure == RUN_HALTED:
                    # Halted in the wait before anything of this listing came: the same as a halt
                    # before the step. Pages already read leave a partial listing, said below.
                    await self._skip(step.method, RUN_HALTED)
                elif not self._rejected:
                    await self._unanswered_step(step.method, page, self._failure)
                return False
            self._sent.append(step.method)
            if step.method == "tools/list":
                self._remember_tools(answer)
            if not step.paginate:
                return True
            result = answer.get("result")
            offered = result.get("nextCursor") if isinstance(result, dict) else None
            if offered is not None and not isinstance(offered, str):
                # Neither the end nor a cursor that could be sent back: the listing is cut
                # short at a point the server chose, and must not read as complete. An answer
                # did come, so the script goes on with its next step.
                await self._unanswered_step(step.method, page + 1, CURSOR_INVALID)
                return True
            cursor = _text_or_none(offered)
            if cursor is None:
                return True
            if page + 1 >= MAX_PAGES:
                # The listing is not complete and must not read as if it were.
                await self._skip(step.method, PAGE_LIMIT, detail=str(MAX_PAGES))
        return True

    async def _may_ask(
        self,
        step: Step,
        pages: int,
        before_request: Callable[[str], Awaitable[None]] | None,
    ) -> bool:
        """Whether a listing may send one more request, ``pages`` being the pages it has got."""
        if self._halt_reason() is not None:
            await self._skip(step.method, RUN_HALTED, detail=str(pages))
            return False
        if before_request is not None:
            await before_request(step.method)
        return True

    def _remember_tools(self, answer: dict[str, Any]) -> None:
        """The names a ``tools/list`` answer delivered: what a later ``call`` may name."""
        result = answer.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if isinstance(tools, list):
            self._listed.update(
                tool["name"]
                for tool in tools
                if isinstance(tool, dict) and isinstance(tool.get("name"), str)
            )

    async def _call(self, step: CallStep) -> bool:
        """One tool call. False when an answer never came; an error answer is an answer: it is
        recorded, and the script goes on."""
        if self._guard is not None:
            cause = self._guard.cause(step.tool)
            if cause is not None:
                return await self._refuse(step, cause)

        async def sent() -> None:
            self._called.append(step.tool)
            if self._record_called is not None:
                await self._record_called(
                    step=step.method, tool=step.tool, arguments=step.arguments, check=step.check
                )

        answer = await self._request(
            step.method,
            {"name": step.tool, "arguments": step.arguments},
            timeout=step.timeout,
            on_sent=sent,
        )
        if answer is None:
            if self._failure == RUN_HALTED:
                await self._skip(step.method, RUN_HALTED)  # as a halt before the step
            elif not self._rejected:
                await self._unanswered_step(step.method, 0, self._failure)
            return False
        self._sent.append(step.method)
        failure = _call_failure(answer)
        if failure is UNREADABLE:
            # An answer came, and nothing can be read out of it: neither a result nor an error.
            # The step says so, as a cursor that cannot be sent back does, and the script goes
            # on — the channel is fine, only this answer is not one.
            await self._unanswered_step(step.method, 0, UNREADABLE)
            return True
        if failure is not None:
            kind, code = failure
            self._failed.append(step.tool)
            if self._record_call_failed is not None:
                await self._record_call_failed(
                    step=step.method, tool=step.tool, kind=kind, code=code
                )
        return True

    async def _refuse(self, step: CallStep, cause: str) -> bool:
        """A call the engagement does not allow reached the driver: the gate should have refused
        the script, so this is a mistake of the tool. Nothing is sent; the call and every step
        after it say so as ``driver_error``, the guard's cause is recorded, and the script ends."""
        name = step.tool
        self._blocked = (cause, name)
        self._notice(
            f"the scope guard did not let the probe {self._probe.name} call a tool ({cause})"
            if self._probe is not None
            else f"the scope guard stopped a call it had to refuse earlier ({cause})"
        )
        if self._record_blocked is not None:
            await self._record_blocked(cause=cause, where=BLOCKED_BY_DRIVER, tool=name)
        await self._skip(
            step.method, DRIVER_ERROR, detail="the engagement does not allow this call"
        )
        self._failure = DRIVER_ERROR
        return False

    def _reissue_wanted(self) -> bool:
        """Whether the last request's response stream broke in the modern era: "a broken response
        stream loses the in-flight request; clients MUST re-issue it as a new request with a new
        request ID" (2026-07-28). Once: the second break is the step's."""
        return self._era == eras.ERA_MODERN and self._failure == STREAM_BROKEN

    async def _reissued(self, step: str, page: int) -> None:
        if self._record_reissued is not None:
            await self._record_reissued(step=step, page=page, reason=STREAM_BROKEN)

    # -- the wire --------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        params: dict[str, Any] | None,
        *,
        timeout: float | None = None,
        on_sent: Callable[[], Awaitable[None]] | None = None,
    ) -> dict[str, Any] | None:
        """The answer, or None with the reason in ``_failure``. ``on_sent`` runs once the
        request is on its way and before its answer is waited for."""
        identifier = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": identifier, "method": method}
        if self._meta is not None:
            # The modern era has no handshake: every request says which version and whose it is.
            params = {**(params or {}), "_meta": self._meta}
        if params is not None:
            message["params"] = params
        return await self._transact(message, timeout=timeout, on_sent=on_sent)

    async def _transact(
        self,
        message: dict[str, Any],
        *,
        timeout: float | None = None,
        on_sent: Callable[[], Awaitable[None]] | None = None,
        lenient: bool = False,
    ) -> dict[str, Any] | None:
        """Send one request and wait for its answer. ``lenient``: an answer with a null id counts
        as the answer too — the body of a 400 to the probe — and is the only message that does."""
        budget = self._timeout if timeout is None else timeout
        deadline = _monotonic() + budget
        answer = await self._attempt(message, budget, on_sent, lenient)
        status = self._rate_limit_wait(deadline)
        if status is None:
            self._note_exchange(message, answer)
            return answer
        seconds = self._channel.retry_after
        # The same request, once more, after the wait: its id is the one the answer is matched
        # by. ``on_sent`` ran for the first send and does not run again.
        await self._waited(seconds, status)
        # The wait may have outlasted the window, or the stop file may have appeared in it: the
        # same question as before every step, and no request goes out on a "halt". The step ends
        # with the halt's own reason, not ``rate_limited``; the ``paced`` of the wait stands.
        if self._halt_reason() is not None:
            self._failure = RUN_HALTED
            self._failure_detail = ""
            self._note_exchange(message, None)  # the one request that went out, and its 429/503
            return None
        # Nothing may be left of the step after the wait: then no request goes out, the server
        # never had the time to answer it, and the step stays ``rate_limited`` (the failure of
        # the first answer), with the ``paced`` of the wait.
        if deadline - _monotonic() <= 0:
            self._note_exchange(message, None)
            return None
        # Whatever 429 or 503 comes back now is the "second" one: ``rate_limited``, header or not.
        self._channel_after_wait(True)
        try:
            answer = await self._attempt(message, deadline - _monotonic(), None, lenient)
        finally:
            self._channel_after_wait(False)
        self._note_exchange(message, answer)
        return answer

    def _note_exchange(self, message: dict[str, Any], answer: dict[str, Any] | None) -> None:
        """Under a token observation: how the server answered this request, one entry for each
        request sent.

        ``accepted`` is true only for a 2xx whose answer is a JSON-RPC result to this request: a
        ``result`` object and no ``error`` key at all. It follows how the recording's own message
        analysis reads an answer (``events.analyse``: an ``error`` key makes it an error), so an
        ``error`` beside a result, even ``null``, makes it no result. False for 401 and 403,
        always — whatever became of the body, which is read for its code alone and may never have
        come; null in every other case (no answer, another status, an error answer, an answer
        without a result, an answer with a result and an ``error`` key), where ``http_status``
        and ``rpc_code`` say what came. A 401 or 403 ends the run at this exchange, and the
        failure is its own word. ``rpc_code`` is a JSON-RPC error's code: of the answer, or of
        the body of the 401 or 403. Both numbers come from the server, so each is kept only
        within bounds (:meth:`_code`, :func:`_http_status`)."""
        if self._observation is None:
            return
        method = str(message.get("method"))[: events.MAX_METHOD_LENGTH]
        self._take_probe_as_opening(method)
        role = self._role(method)
        status = _http_status(getattr(self._channel, "answer_status", None))
        # The channel names the refusal at the head, before the body is read: a body that stalls
        # or breaks off may leave the step without an answer, and the refusal stands.
        refused = answer is None and (
            self._failure == UNAUTHORIZED or getattr(self._channel, "failure", None) == UNAUTHORIZED
        )
        if refused:
            self._exchanges.append(
                {
                    "role": role,
                    "method": method,
                    "accepted": False,
                    "http_status": _http_status(
                        getattr(self._channel, "unauthorized_status", None)
                    ),
                    "rpc_code": self._code(getattr(self._channel, "rejection_code", None)),
                }
            )
            self._rejected = True
            self._failure = OBSERVATION_REJECTED
            return
        error = answer.get("error") if answer is not None else None
        taken = (
            answer is not None
            and status is not None
            and 200 <= status < 300
            and isinstance(answer.get("result"), dict)
            and "error" not in answer
        )
        self._exchanges.append(
            {
                "role": role,
                "method": method,
                "accepted": True if taken else None,
                "http_status": status,
                "rpc_code": self._code(error.get("code") if isinstance(error, dict) else None),
            }
        )

    def _code(self, code: Any) -> int | None:
        """A JSON-RPC error code the server named, or None: a whole number within
        :data:`MAX_CODE` that holds no literal of the run in its decimal form and is no known
        value (a server may reflect a token or a known value there)."""
        if type(code) is not int or abs(code) > MAX_CODE:
            return None
        if self._is_literal is not None and self._is_literal(code):
            return None
        return code

    def _take_probe_as_opening(self, method: str) -> None:
        """In the new era ``server/discover`` is the opening. It is the era detection's probe only
        when the run goes on to send ``initialize``, the old era's opening: then the exchange
        that was noted as the opening is the probe."""
        if method != "initialize":
            return
        for exchange in self._exchanges:
            if exchange["method"] == eras.PROBE_METHOD:
                exchange["role"] = events.ROLE_ERA_PROBE

    def _role(self, method: str) -> str:
        """What a request is within the run: the opening (``server/discover`` or ``initialize``),
        a listing, a call — or, in the run of a probe module, one the module made."""
        if method in (eras.PROBE_METHOD, "initialize"):
            return events.ROLE_OPENING
        if self._probe is not None:
            return events.ROLE_PROBE
        return events.ROLE_LIST if method.endswith("/list") else events.ROLE_CALL

    def _channel_after_wait(self, value: bool) -> None:
        """Tell the channel (if it is one that reads statuses) that the request now sent is the
        one after a ``Retry-After`` wait."""
        if hasattr(self._channel, "after_wait"):
            self._channel.after_wait = value

    def _rate_limit_wait(self, deadline: float) -> int | None:
        """The status (429 or 503) of the answer the last send drew, when it asked for a wait in
        seconds that fits what the step has left; else None, and the failure stands as
        ``rate_limited``. A 429 without ``Retry-After``, a date, and a wait as long as the time
        left (nothing would remain to read the answer in) are not waited for."""
        if self._failure != RATE_LIMITED:
            return None
        seconds = getattr(self._channel, "retry_after", None)
        status = getattr(self._channel, "rate_limit_status", None)
        if seconds is None or status is None or seconds >= deadline - _monotonic():
            return None
        return status

    async def _waited(self, seconds: int, status: int) -> None:
        """Wait ``seconds`` and say so as ``paced{seconds, why: "retry_after", status}``."""
        began = _monotonic()
        await _sleep(seconds)
        if self._record_paced is not None:
            await self._record_paced(
                seconds=max(_monotonic() - began, float(seconds)),
                why=events.PACED_RETRY_AFTER,
                status=status,
            )

    async def _attempt(
        self,
        message: dict[str, Any],
        timeout: float,
        on_sent: Callable[[], Awaitable[None]] | None,
        lenient: bool,
    ) -> dict[str, Any] | None:
        """One send of ``message`` and the wait for its answer, within ``timeout``."""
        identifier = message["id"]
        self._failure = NO_ANSWER
        self._failure_detail = ""
        try:
            await self._send(message)
            if on_sent is not None:
                await on_sent()
            return await self._answer_to(identifier, timeout, lenient=lenient)
        except OversizedTimeout:
            self._failure = UNREADABLE
            return None
        except asyncio.TimeoutError:
            return None
        except (ConnectionError, OSError):
            self._failure = CLOSED
            return None

    async def _send(self, message: dict[str, Any]) -> None:
        line = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        await self._channel.send(line)

    async def _answer_to(
        self, identifier: int, timeout: float | None = None, *, lenient: bool = False
    ) -> dict[str, Any] | None:
        """Read until the answer to this id arrives.

        Matched by id, never by position: a server may send notifications, log lines and
        progress between a question and its answer, and the reference handshake does exactly
        that. Anything else that arrives is read past — including a request of the server's
        own, which is *not* answered: this client announced no capabilities, so a conforming
        server sends none, and inventing an answer here would be client behaviour nobody
        asked this tool to have.

        An answer is a message **without** ``method`` (:func:`_answers`). A request of the
        server's own may carry the very id this client is waiting on — ids are per sender —
        and taken as the answer it would end the step with no answer given: a ``tools/list``
        with no tools, an inventory complete that never listed one.

        The time is one per step, not one per line: the wait ends ``step_timeout`` after it
        began, however many other lines the server sends meanwhile. A server that sends a line
        just before each time runs out would otherwise hold a step for ``MAX_INTERLEAVED``
        times the timeout. ``MAX_INTERLEAVED`` stays as the second limit. A step that names its
        own time (a call's ``timeout``) is given that one instead of the run's.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (self._timeout if timeout is None else timeout)
        for _ in range(MAX_INTERLEAVED):
            remaining = deadline - loop.time()
            if remaining <= 0:
                # Out of time, and no line is read with a time of zero or less: a channel
                # might take that for "at once" or for "never".
                return None
            line = await self._channel.read_line(remaining)
            if line is None:
                # A reason the channel names (HTTP only) is the reason of the step; failing
                # that, an unreadable line before the end says more than the end does.
                named = getattr(self._channel, "failure", None)
                if named is not None:
                    self._failure = named
                    self._failure_detail = getattr(self._channel, "failure_detail", "")
                elif self._failure != UNREADABLE:
                    self._failure = CLOSED
                return None
            if line == OVERSIZED:
                self._failure = UNREADABLE
                continue
            document, too_deep = load_bytes(line, MAX_READ_DEPTH)
            if too_deep:
                # Unreadable at the same depth on every Python version, not wherever its own
                # json.loads gives out. If it is the answer, there is no other to wait for:
                # its id is read from the top level alone. One whose top level names a method
                # is a request or notification of the server's own: the answer was not among
                # it, so it does not make the answer unreadable either.
                if _answers(document, identifier, lenient):
                    self._failure = UNREADABLE
                    return None
                if not (isinstance(document, dict) and "method" in document):
                    self._failure = UNREADABLE
                continue
            if _answers(document, identifier, lenient):
                return document
        return None

    # -- what was not sent -----------------------------------------------------------

    async def _skip(self, step: str, reason: str, *, detail: str = "") -> None:
        self._skipped.append((step, reason))
        await self._record_skipped(step=step, reason=reason, detail=detail)

    async def _skip_remaining(self, steps, reason: str) -> None:
        for step in steps:
            await self._skip(step.method, reason)

    async def _unanswered_step(self, step: str, pages: int, reason: str) -> None:
        """A step sent and not answered in full. Its ``detail`` is the channel's text under
        ``tls``, and empty for every other reason."""
        detail = self._failure_detail if reason == TLS else ""
        self._unanswered.append((step, pages, reason, detail))
        if self._record_unanswered is not None:
            await self._record_unanswered(step=step, pages=pages, reason=reason, detail=detail)


class _ProbeContext:
    """The context of one module's run (:class:`mcp_kymograph.probes.base.Context`).

    Before each request: has the run been told to stop (the window, the stop file, a signal),
    and has the module used its ``max_calls``. A call must name a tool a ``tools/list`` of this
    run delivered, as a script's call must, and then goes through :meth:`Driver._call`, where the
    scope guard holds it against the engagement. What stops a request is recorded as a step that
    was not sent, with the word of the cause, and ends the module (:class:`ProbeEnded`)."""

    def __init__(self, driver: Driver, probe: Probe, capabilities: dict[str, Any]) -> None:
        self._driver = driver
        self._probe = probe
        self._capabilities = capabilities
        self._used = 0

    async def tools(self) -> frozenset[str]:
        driver, step = self._driver, Step("tools/list", requires="tools", paginate=True)
        await self._not_halted(step.method)
        reason = _why_not(step, self._capabilities)
        if reason is not None:
            await self._end(step.method, reason)
        await self._admit(step.method)
        if not await driver._listing(step, before_request=self._admit):
            raise ProbeEnded(driver._failure)
        return frozenset(driver._listed)

    async def call(
        self, tool: str, arguments: Mapping[str, Any] | None = None, *, timeout: float | None = None
    ) -> CallResult:
        driver = self._driver
        step = CallStep(tool=tool, arguments=dict(arguments or {}), timeout=timeout)
        await self._not_halted(step.method)
        reason = _why_not(step, self._capabilities)
        if reason is None and tool not in driver._listed:
            reason = TOOL_NOT_LISTED
        if reason is not None:
            await self._end(step.method, reason)
        await self._admit(step.method)
        failed_before = len(driver._failed)
        if not await driver._call(step):
            raise ProbeEnded(driver._failure)
        return CallResult(failed=len(driver._failed) > failed_before)

    async def pace(self) -> None:
        """The hook for a pause before a request. It has no effect on the interval: that holds for
        the whole run and is kept before the first exchange (mcp_kymograph.pacing). An interval per
        probe request belongs to a later step."""

    async def _not_halted(self, method: str) -> None:
        if self._driver._halt_reason() is not None:
            await self._end(method, RUN_HALTED)

    async def _admit(self, method: str) -> None:
        if self._used >= self._probe.max_calls:
            await self._end(method, PROBE_CALLS_EXHAUSTED)
        self._used += 1
        await self.pace()

    async def _end(self, method: str, reason: str) -> None:
        """A request that is not sent: said as a step that was not, and the module is over."""
        await self._driver._skip(method, reason)
        raise ProbeEnded(reason)


def _answers(document: Any, identifier: int, lenient: bool = False) -> bool:
    """Whether a message is the answer to request ``identifier``: an object with that id and
    without ``method``. A request or notification of the server's own is never an answer,
    whatever its id. Nor is an id ``true``, which ``==`` takes for ``1``: no client does. With
    ``lenient``, an object with ``"id": null`` and an ``error`` is one too: a server cannot name
    the id of a request it could not read, and answers a modern probe it refused so."""
    if not isinstance(document, dict) or "method" in document:
        return False
    found = document.get("id")
    if lenient and found is None and "id" in document and isinstance(document.get("error"), dict):
        return True
    return not isinstance(found, bool) and found == identifier


def _http_status(status: Any) -> int | None:
    """An HTTP status as a number to keep: one from 100 to 599, else None."""
    return status if type(status) is int and 100 <= status <= 599 else None


def _call_failure(answer: dict[str, Any]) -> tuple[str, int | None] | str | None:
    """Whether a call's answer is an error, and which kind; None for a result.

    A ``result`` object is the result — a tool error if it says ``isError`` is true — even
    beside an ``error`` key, as the SDKs read it. Failing that, an ``error`` object is a
    JSON-RPC error answer, with its code if that is a number. Anything else — ``"result":
    null``, a result that is no object, neither key — is no answer anybody can read:
    :data:`UNREADABLE`, never a success. So is a result whose ``isError`` is there and not a
    boolean (``"true"``, ``1``, ``null``): the SDKs read that differently, so it is neither a
    success nor a tool error guessed at.
    """
    result = answer.get("result")
    if isinstance(result, dict):
        flag = result.get("isError", False)
        if flag is True:
            return CALL_TOOL_ERROR, None
        return None if flag is False else UNREADABLE
    error = answer.get("error")
    if not isinstance(error, dict):
        return UNREADABLE
    code = error.get("code")
    if isinstance(code, bool) or not isinstance(code, int) or abs(code) > MAX_CODE:
        code = None
    return CALL_RPC_ERROR, code


def _why_not(step: Step | CallStep, capabilities: dict[str, Any]) -> str | None:
    """Whether this step may be sent, and if not, in our own words why not."""
    if step.requires not in capabilities:
        return NOT_OFFERED
    if not isinstance(capabilities[step.requires], dict):
        # The protocol says a capability is an object. Anything else is not something to
        # read intent out of, so it is treated as not offered — fail closed, and say which.
        return MALFORMED_CAPABILITY
    return None


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _differs(declared: dict[str, Any] | None, detection: eras.Detection) -> bool | None:
    """Whether the generation (and version, if it names one) the engagement file declares is
    another than the one the detection found; None without a declaration, or when the detection
    found no generation to compare."""
    if declared is None or detection.era is None:
        return None
    if declared.get("era") != detection.era:
        return True
    version = declared.get("version")
    return version is not None and detection.version is not None and version != detection.version


def _stop_facts(detection: eras.Detection) -> dict[str, Any]:
    """What a stop with ``protocol_unsupported`` has to say to the terminal, as the server said
    it, limited in number and not in text: its reason, the error's code, the capabilities it
    requires, the versions it names, and the one it answered ``initialize`` with."""
    error = detection.error or {}
    data = error.get("data") if isinstance(error.get("data"), dict) else {}
    required = data.get("requiredCapabilities")
    probe = detection.probe
    return {
        "reason": detection.reason,
        "code": error.get("code"),
        "required": [str(key) for key in list(required)[:MAX_NAMED]]
        if isinstance(required, dict)
        else [],
        "versions": list(probe.supported) if probe is not None else [],
        "version": detection.version,
    }


def _stop_words(detection: eras.Detection) -> str:
    """Our own sentence for a stop, for the recording's ``detail`` (masked, then cut, there)."""
    facts = _stop_facts(detection)
    if detection.reason == eras.MODERN_REFUSED:
        return (
            f"the server refused the modern probe with error {facts['code']}: it requires "
            "what this tool does not offer, or finds the request's headers and body at odds"
        )
    if detection.reason == eras.NO_COMMON_VERSION:
        named = ", ".join(facts["versions"]) or "none"
        if eras.MODERN_VERSION in facts["versions"]:
            return (
                f"the server rejected protocol version {eras.MODERN_VERSION} although it names "
                f"it as supported (it names: {named})"
            )
        return f"the server names no protocol version this tool speaks (it names: {named})"
    if detection.reason == eras.UNKNOWN_VERSION:
        return (
            f"initialize was answered with protocol version {facts['version']}, which this "
            "tool does not know"
        )
    return "initialize was answered with a protocolVersion that is no version"


async def run_driven(proxy: Proxy, driver: Driver) -> RunOutcome:
    """Run the proxy and the script together, and return the run's outcome.

    The proxy is awaited, not the driver: the run ends when the client's end of input reaches
    it, and the driver produces that end of input as its last act. If the proxy stops first —
    a server that will not start, a duration limit, a signal — the driver is cancelled with
    it rather than left waiting for an answer that cannot come. Before its closing event the
    proxy waits, bounded, for the driver to have written how its script ended
    (``client_settled``): the driver learns of the end when its channel closes, and what it
    then writes belongs in the recording, not after it.
    """
    settled = asyncio.Event()
    proxy.client_settled = settled

    async def converse() -> None:
        # Speak once the server exists. A server that will never exist — the sandbox did not
        # hold — gets no conversation at all: there is nobody to have it with.
        try:
            await proxy.launched.wait()
            if proxy.ready:
                await driver.run()
        finally:
            settled.set()

    task = asyncio.create_task(converse(), name="driver")
    try:
        return await proxy.run()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
