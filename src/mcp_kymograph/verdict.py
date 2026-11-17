"""What a driven run is worth, read back from its recording: a result, or how it falls short.

A run is judged from the **artifact**, the recording, not from what the process that made it
believed. Each shortfall found is one of three kinds, and the run takes the state of the
gravest it has:

* ``sandbox_failed`` — the isolation, or the observation of what the target sent, was not
  established or did not hold. Nothing the run shows can be trusted as an observation.
* ``server_failed`` — the target never completed the handshake. Nothing was observed.
* ``incomplete`` — data is missing: the recording ends early, a line cannot be read, a finding
  the inspector counted is not in it, a listing went unanswered or was cut off, the sink missed
  datagrams the target sent. A finding it lacks may only be missing.

A run with none of them is ``complete``: a result. A recorded cap is not a shortfall — what was
cut, and why, is known — and is kept as a *truncation* beside the state: findings past the
per-message cap (``findings_capped``, with the true numbers), a listing cut at the driver's
page limit. Analogous to ``path_not_found`` against silently missing.

**A driven run proves its inventory, it is not presumed to have one.** The driver writes
``script_finished`` once its script has reached its end; a script that was cut off writes
nothing, so a driven run without that event is incomplete. Absence of a failure is not
evidence of a full inventory.

**Every state has its own exit code, and none of them can be a server's.** In driver mode the
server's own exit status is recorded (``server_exited``) and carried here as ``server_exit``;
it is never handed through. A batch that reads ``3`` knows the tool found data missing, not
that some server happened to end with 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_kymograph.events import (
    CALL_FAILURES,
    CALL_RPC_ERROR,
    HTTP_COUNTS,
    HTTP_SSE_ONLY,
    HTTP_STATUS,
    HTTP_UNREACHABLE,
    MAX_READ_DEPTH,
    OBSERVATION_REJECTED,
    PAGE_LIMIT,
    PARTIAL_REASONS,
    PROTOCOL_UNSUPPORTED,
    RATE_LIMITED,
    SCHEMA_VERSION,
    SESSION_LOST,
    STREAM_BROKEN,
    TLS,
    TOKEN_OBSERVATIONS,
    TOOL_NOT_LISTED,
    TRANSPORT_HTTP,
    UNAUTHORIZED,
    UNREADABLE,
    load_bytes,
)
from mcp_kymograph.inspection import server_field

COMPLETE = "complete"
INCOMPLETE = "incomplete"
SERVER_FAILED = "server_failed"
SANDBOX_FAILED = "sandbox_failed"
#: A run whose data is all there and in which the server answered a tool call of the script
#: with an error. Not a failure of the run — the server answered — and not a result about the
#: content the call was to deliver, which never came.
CALL_FAILED = "call_failed"

#: Gravest first. A run that is several of these is the first of them: a sandbox that did not
#: hold explains a server that never answered, and a server that never answered explains the
#: data that is missing — never the other way round. A refused call says less than missing
#: data: a run that lacks data is incomplete, whatever its calls did.
STATES = (SANDBOX_FAILED, SERVER_FAILED, INCOMPLETE, CALL_FAILED, COMPLETE)

EXIT_COMPLETE = 0
EXIT_INCOMPLETE = 3
EXIT_SERVER_FAILED = 4
EXIT_SANDBOX_FAILED = 5
EXIT_CALL_FAILED = 6

EXIT_CODES = {
    COMPLETE: EXIT_COMPLETE,
    INCOMPLETE: EXIT_INCOMPLETE,
    SERVER_FAILED: EXIT_SERVER_FAILED,
    SANDBOX_FAILED: EXIT_SANDBOX_FAILED,
    CALL_FAILED: EXIT_CALL_FAILED,
}

#: The version of the rules a run is judged by. Raised with every change to what makes a run
#: complete, incomplete or failed, and to what a fleet's digest covers — never for a change to
#: how a store or a recording is laid out, which is a schema. Kept with every result: each run
#: and each fleet in the store, the output of ``kymograph verdict``, a fleet's digest. A
#: comparison across two versions says so, because it compares the rules as well as the servers.
#: tests/test_rules_version.py pins what the rules make of a fixed set of recordings for each
#: version, so a rule that changes without this number fails there.
#:
#: 1. The rules stores of schema 7 and 8 were judged by: UDP reconciled destination by
#:    destination, any UDP loss incomplete (:data:`UDP_LOSS_LIMIT`), a cause for every shortfall.
#: 2. A session in which nobody said anything is incomplete (``empty_session``).
#: 3. A fleet's digest carries each result's causes.
#: 4. A run stopped by a signal (``run_stopped``) is incomplete, cause ``interrupted``; what the
#:    stop brought about after it — a server killed before it answered — is not held against the
#:    server.
#: 5. A step the driver could not read an answer to (``answer_unreadable``) leaves the inventory
#:    partial, as one that was not answered does.
#: 6. A sandbox that failed after the target, or in a phase not recorded, has a cause of its own
#:    (``sandbox_failed_after_target``); ``sandbox_failed`` is only the failure before the target
#:    existed.
#: 7. A server message that is not valid UTF-8 is incomplete, cause ``message_undecodable``: a
#:    client reads it with replacement characters, so what was inspected is not exactly what was
#:    sent, and no rule can act on bytes it cannot read. A client message that is not valid
#:    UTF-8 is incomplete for a cause of its own, ``client_message_undecodable``: the client's
#:    doing, not held against the server.
#: 8. Over Streamable HTTP, a handshake or a step that failed for a reason only HTTP knows has a
#:    cause of its own — ``http_unreachable``, ``http_status``, ``session_lost``,
#:    ``http_sse_only`` — instead of ``server_failed`` or ``step_unanswered``; the states are
#:    those the same failure has over stdio. An HTTP run whose ``run_finished`` lacks the counts
#:    made where traffic was forwarded, or whose counts are not counts, is incomplete
#:    (``http_counts_missing``). A step skipped for a reason that is no string was not sent.
#: 9. A script that calls tools: a call the server answered with an error is a state of
#:    its own, ``call_failed`` (cause ``call_error`` for a JSON-RPC error, ``tool_error`` for a
#:    result with ``isError``), between ``incomplete`` and ``complete``; an answer to a call that
#:    could not be read is incomplete, cause ``call_result_unreadable``; a call to a tool the
#:    script's listing did not deliver was not sent (``step_not_sent``); a ``call_failed`` record
#:    that is not one is incomplete (``call_record_unreadable``).
#: 10. Isolation ``remote``: an endpoint this tool does not run, reached over the operator's own
#:    connection (docs/design/http-transport.md 4.1). A run that names it is judged as one under
#:    ``host`` is — its egress is not observed, so no account of it is asked for — where under 9
#:    it was incomplete (``unknown_isolation``).
#: 11. Over HTTPS, a handshake with the endpoint that failed — a certificate that does not verify,
#:    a name that does not match, no protocol both sides speak — has a cause of its own, ``tls``
#:    (docs/design/http-transport.md 8.3): ``server_failed`` on the first exchange, ``incomplete``
#:    on a later one, the states the same failure has anyway. Under 10 the same recording was
#:    named by the general cause, ``server_failed`` or ``step_unanswered``; the channel of 10,
#:    which spoke no TLS, would have called the failed connection ``http_unreachable``.
#: 12. An endpoint that answers 401 or 403 has a cause of its own, ``unauthorized``:
#:    ``server_failed`` on the first exchange, ``incomplete`` on a later one, the states the same
#:    failure has anyway. Under 11 the same recording was named by the general cause,
#:    ``server_failed`` or ``step_unanswered``. Rules
#:    12 cover ``unauthorized``, ``stream_broken`` (a response stream that ended before its
#:    answer, twice in the modern era) and ``protocol_unsupported`` (the detection of the
#:    server's generation stopped: ``server_failed``, no listing sent), by the same rule.
#: 13. An endpoint that answers 429, or 503 with ``Retry-After``, and goes on doing so after the
#:    one wait this tool makes (or asks for more than the step has left, or for a date), has a
#:    cause of its own, ``rate_limited``:
#:    ``server_failed`` on the first exchange, ``incomplete`` on a later one, the states the same
#:    failure has anyway. Under 12 the same recording was named by the general cause,
#:    ``server_failed`` or ``step_unanswered``. A 503 without ``Retry-After`` stays
#:    ``http_status``. The ``paced`` event is passed by.
#: 14. A token observation (``run_started.auth.observation`` is set: a token for another audience,
#:    an expired one, or none) that ends because the endpoint answered 401 or 403 is ``complete``:
#:    the refusal is its result, not a failure, and ``token_observation`` has the exchanges. The
#:    steps skipped for that, with the reason ``observation_rejected``, are no gap. Every other
#:    cause (a timeout, ``rate_limited``, a connection that broke off, ...) stands as it did.
#:    Without ``observation`` nothing changes: a step skipped as ``observation_rejected`` is
#:    one that was not sent (``step_not_sent``), as one skipped for ``unauthorized`` is, and a
#:    401 or 403 is ``unauthorized`` under 12. The refusal also goes before the check for silence
#:    (``server_silent``), for a 401 or 403 with no body byte at all is the usual answer of a
#:    real server: when ``token_observation`` has an exchange with ``accepted: false`` and the
#:    status 401 or 403, and a step was skipped as ``observation_rejected``, the run did not end
#:    in silence. A run that is no observation, or that ends otherwise, is judged as before.
RULES_VERSION = 14

#: The reasons only HTTP knows (mcp_kymograph.events), each the key of its own cause: a step or a
#: handshake that failed for one of them is named by it, in the state the failure has anyway.
HTTP_CAUSES = {
    HTTP_UNREACHABLE: "http_unreachable",
    HTTP_STATUS: "http_status",
    SESSION_LOST: "session_lost",
    HTTP_SSE_ONLY: "http_sse_only",
    TLS: "tls",
    UNAUTHORIZED: "unauthorized",
    STREAM_BROKEN: "stream_broken",
    RATE_LIMITED: "rate_limited",
    PROTOCOL_UNSUPPORTED: "protocol_unsupported",
}

#: Isolations a recording may name, and which of them carry an account of the target's egress.
#: ``remote`` carries none: the server runs on somebody else's machine, and what it sends
#: anywhere but to this tool is not observed.
ISOLATIONS = ("host", "runc", "remote")
OBSERVED_ISOLATIONS = ("runc",)

#: The share of the target's UDP datagrams the sink may have missed for the run to count as
#: observed: none. The kernel's record still names every destination and count, so a lossy run
#: is not one whose sandbox failed — but what a lost datagram carried, a DNS name or a payload,
#: was not observed, and that can be the one datagram that mattered: a name that tunnels data
#: out looks like every other question. Any positive tolerance is one a target can aim under —
#: fill the sink's queue with decoys, then send the datagram that counts — so a target may
#: make its run incomplete by flooding, never make it read as complete. Measured:
#: no loss for anything short of a burst of hundreds of datagrams within milliseconds.
UDP_LOSS_LIMIT = 0.0


#: Why a run falls short: one stable key per kind of shortfall. A store, a fleet and a report
#: tell shortfalls apart by these — a run incomplete because the sink missed datagrams
#: (``udp_loss``) from one incomplete because a listing went unanswered — and count and query
#: them; the reason beside each key says the particulars in words. Every shortfall has exactly
#: one, and only these exist.
CAUSES: dict[str, str] = {
    "unreadable": "the recording cannot be read from disk",
    "schema": "the recording is of another schema, and is judged by nothing else",
    "line": "a line of the recording is not JSON, or not an event object",
    "no_run_started": "the recording does not begin with run_started",
    "no_run_finished": "the recording ends before run_finished",
    "recording_stopped": "writing stopped during the run; everything after it is missing",
    "unwritten_events": "events the run made were never written",
    "inspection_bounded": "messages were only partly inspected",
    "message_undecodable": "a server message was not valid UTF-8: inspected as a client decodes "
    "it, not as it was sent, and no rule acted on it",
    "client_message_undecodable": "a client message was not valid UTF-8: the client's doing, not "
    "the server's",
    "call_error": "a tool call of the script was answered with a JSON-RPC error",
    "tool_error": "a tool call of the script was answered with a result that says isError",
    "call_result_unreadable": "the answer to a tool call could not be read: longer than the "
    "message limit, nested too deeply, or neither a result nor an error",
    "call_record_unreadable": "a call_failed record that names no tool or no known kind",
    "counts_missing": "run_finished has no findings counts to check the recording against",
    "findings_missing": "a statement counted findings the recording does not hold",
    "findings_uncounted": "the recording holds findings no statement counted",
    "cap_unaccounted": "a findings cap does not say what it cut",
    "step_unanswered": "a step of the script was sent and not answered in full",
    "step_not_sent": "a step of the script was not sent for a reason that leaves it short",
    "no_script_finished": "the driver's script never recorded its end",
    "unknown_isolation": "the recording names an isolation this tool does not know",
    "no_egress_summary": "a sandboxed run without the account of what its target sent",
    "udp_loss_unknown": "the account of the target's egress says nothing readable about loss",
    "udp_loss": "the sandbox's sink missed UDP datagrams the target sent",
    "server_failed": "the server never started, or never completed the handshake",
    "http_unreachable": "the HTTP endpoint could not be reached, or closed the connection before "
    "it answered",
    "http_status": "the server answered a request with an HTTP status that carries no answer",
    "session_lost": "the server ended or refused the session before the script finished",
    "http_sse_only": "the endpoint speaks only the deprecated HTTP+SSE transport, which is "
    "detected and not driven",
    "tls": "the TLS handshake with the endpoint failed: a certificate that does not verify, a "
    "name that does not match, or no protocol both sides speak; the library's text is in the "
    "recording",
    "unauthorized": "the endpoint answered 401 or 403: it did not accept the client's "
    "credentials, or none; the challenge it sent is in the recording",
    "stream_broken": "a response stream ended before the answer to its request did, and again on "
    "the request sent a second time",
    "rate_limited": "the endpoint answered 429, or 503 with Retry-After, and did so again after "
    "the one wait this tool makes, or asked for longer than the step had left; a 429 without "
    "Retry-After is this at once",
    "protocol_unsupported": "the server requires what this tool does not offer, or speaks no "
    "protocol version it knows: no listing was sent, and the run is not a result",
    "http_counts_missing": "an HTTP run's run_finished has no counts of what was forwarded",
    "server_silent": "the server wrote nothing — to its stdout, or in the bodies of its HTTP "
    "answers — though asked or before its client",
    "server_output_unknown": "run_finished does not say whether the server wrote anything",
    "empty_session": "neither the server nor its client wrote anything: a session about nothing",
    "sandbox_failed": "the sandbox could not be built, or did not hold, before the target existed",
    "sandbox_failed_after_target": "the sandbox did not hold after the target ran, or which phase "
    "it failed in is not recorded",
    "egress_inconsistent": "the sink's account of the target's egress differs from the kernel's",
    "images_mismatch": "the images that ran are not the ones the environment names",
    "unfiled_finding": "the store could not file a finding under the run's context",
    "interrupted": "stopped by a signal before it ended: the run itself (run_stopped), or a "
    "fleet's run that was stopped or never started and is not filed",
}


def server_silent(output_bytes: int, input_bytes: int, exited_first: bool) -> bool:
    """Whether a server said nothing at all where it had to: it wrote not a byte to its stdout,
    though the client wrote to it — or it ended on its own while its client was still there.

    Either way nothing was observed: a server that crashed on start, or answered nothing. The
    one silence that is not the server's failure is a session in which neither side said
    anything and the client was the one to end it (:func:`empty_session`). One rule for the
    recording (:func:`assess`) and for the exit code of a proxied run, which has no recording
    to read back.
    """
    return output_bytes == 0 and (input_bytes > 0 or exited_first)


def empty_session(output_bytes: int, input_bytes: int, exited_first: bool) -> bool:
    """Whether nobody said anything: neither the server nor its client wrote a byte, and the
    client ended the session.

    Not the server's failure — it was asked nothing — but not a result either: nothing was
    asked and nothing observed, and "complete" about nothing would read as a session that found
    nothing. The same reason a fleet over an empty manifest is refused. Incomplete, under its
    own cause, wherever a session took place (its server ran).
    """
    return output_bytes == 0 and input_bytes == 0 and not exited_first


def gravest(states: Any) -> str:
    """The state of a run that has all of ``states``: the gravest of them, or complete."""
    found = set(states)
    return next((state for state in STATES if state in found), COMPLETE)


@dataclass(frozen=True, slots=True)
class Shortfall:
    state: str
    reason: str
    #: One of :data:`CAUSES`.
    cause: str


@dataclass
class Verdict:
    """The run's state, every reason for it, and what the store needs besides."""

    shortfalls: list[Shortfall] = field(default_factory=list)
    #: Every (statement, signal) the scenario asked for, zeros included.
    statements: set[tuple[str, str]] = field(default_factory=set)
    #: The name the server announced, from ``run_finished``; recorded, never keyed on.
    announced_server: str | None = None
    #: ``{"exit_code", "signal"}`` from ``server_exited``, or None if the server never ran.
    server_exit: dict[str, Any] | None = None
    #: Recorded caps: what was cut, where and why, with the true numbers. Not shortfalls.
    truncations: list[dict[str, Any]] = field(default_factory=list)
    #: Rule 14: an observation run whose token the endpoint turned away, in a recording that
    #: has its end. Such a run is no silence; the exit code of a driven run follows it too.
    refused: bool = False

    @property
    def state(self) -> str:
        return gravest(s.state for s in self.shortfalls)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.state]

    @property
    def problems(self) -> list[str]:
        return [s.reason for s in self.shortfalls]

    @property
    def causes(self) -> list[str]:
        """Every kind of shortfall the run has, each once, sorted."""
        return sorted({s.cause for s in self.shortfalls})

    def add(self, state: str, reason: str, *, cause: str) -> None:
        if cause not in CAUSES:
            raise ValueError(f"{cause!r} is not a cause this verdict knows")
        self.shortfalls.append(Shortfall(state, reason, cause))


def read_events(raw: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """The events of a recording, and a problem for each line that is not one."""
    events: list[dict[str, Any]] = []
    problems: list[str] = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        event, too_deep = load_bytes(line, MAX_READ_DEPTH)
        if too_deep:
            # The recorder writes no document deeper than MAX_RECORDED_DEPTH, so the file is
            # not a recording of ours; said as a problem with the line, never as a crash, at
            # the same depth on every Python version.
            problems.append(f"line {number}: nested too deeply")
            continue
        if event is None:
            problems.append(f"line {number}: not JSON")
            continue
        if not isinstance(event, dict):
            problems.append(f"line {number}: not an event object")
            continue
        events.append(event)
    return events, problems


def read(path: str | Path) -> Verdict:
    """The verdict on one recording on disk. A recording that cannot be read is incomplete —
    and so is one of another schema, which is not judged at all, not even in part."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        return unreadable(exc)
    return judge(*read_events(raw))


def unreadable(exc: OSError) -> Verdict:
    """The verdict on a recording that could not be read: incomplete, and nothing else."""
    verdict = Verdict()
    verdict.add(
        INCOMPLETE, f"the recording cannot be read: {exc.strerror or exc}", cause="unreadable"
    )
    return verdict


def judge(events: list[dict[str, Any]], line_problems: list[str] = ()) -> Verdict:
    """The verdict on a recording's events as :func:`read_events` gives them, for a caller that
    read the bytes itself: one of another schema is not judged at all, not even in part; any
    other is assessed. :func:`read` is this, on a file."""
    foreign = schema_problem(events)
    if foreign is not None:
        verdict = Verdict()
        verdict.add(INCOMPLETE, foreign, cause="schema")
        return verdict
    return assess(events, line_problems)


def schema_problem(events: list[dict[str, Any]]) -> str | None:
    """Why a recording read from disk is not one this version may judge, or None.

    Every line of it must be of :data:`~mcp_kymograph.events.SCHEMA_VERSION`. A recording of an
    older schema lacks what this version's rules ask for, and judging the part it does have
    would pass absence for a result; one of a newer or unknown schema may say things these rules
    do not know. Either is refused whole — by the store, and by the verdict, which then judges
    nothing of it. A recording that does not begin with ``run_started`` is left to the rules
    that say so.
    """
    if not events or events[0].get("type") != "run_started":
        return None
    named = events[0].get("schema_version")
    if named == SCHEMA_VERSION:
        others = sorted({repr(e.get("v")) for e in events if e.get("v") != SCHEMA_VERSION})
        if not others:
            return None
        return (
            f"lines of schema {', '.join(others)} in a recording of schema {SCHEMA_VERSION}: "
            "not one recording of this version; not read, not even in part"
        )
    if isinstance(named, int) and not isinstance(named, bool) and 0 < named < SCHEMA_VERSION:
        return (
            f"the recording is schema {named}, made by an earlier version of Kymograph; this "
            f"version reads schema {SCHEMA_VERSION} only and no older recording, not even in "
            "part — drive the run again"
        )
    return (
        f"the recording is schema {named!r}, which this version does not know (it reads "
        f"{SCHEMA_VERSION}): made by a newer version, or not a recording of this tool; not "
        "read, not even in part"
    )


def assess(events: list[dict[str, Any]], line_problems: list[str] = ()) -> Verdict:
    """Judge a driven run by its events. Says what is wrong; never drops or adds a finding."""
    verdict = Verdict()
    for problem in line_problems:
        verdict.add(INCOMPLETE, problem, cause="line")
    started = events[0] if events and events[0].get("type") == "run_started" else None
    if started is None:
        verdict.add(
            INCOMPLETE, "the recording does not begin with run_started", cause="no_run_started"
        )
    recorded: dict[tuple[str, str], int] = {}
    cut: dict[tuple[str, str], int] = {}
    finished = None
    egress = None
    script_end = None
    unsettled = None
    images = None
    stopped = None
    undecodable = 0
    undecodable_client = 0
    refusal = False
    skipped_for_it = False
    for event in events:
        kind = event.get("type")
        if kind == "message":
            # The recorder says so of every message it could not decode (events.inspect_message).
            # Its presence is the evidence; its absence proves nothing, a message may be dropped,
            # and then the inspector's counts still say it: bounded messages for the server's,
            # client_undecodable for the client's.
            parse = event.get("parse")
            if isinstance(parse, dict) and parse.get("error_reason") == "not_utf8":
                if event.get("direction") == "server_to_client":
                    undecodable += 1
                elif event.get("direction") == "client_to_server":
                    undecodable_client += 1
        elif kind == "finding":
            tally = _tally(event)
            if tally is not None:
                recorded[tally] = recorded.get(tally, 0) + 1
        elif kind == "findings_capped":
            _capped(event, cut, verdict)
        elif kind == "run_finished":
            finished = event
        elif kind == "run_stopped" and stopped is None:
            stopped = event
            verdict.add(
                INCOMPLETE,
                f"run_stopped: the run was stopped by {event.get('signal')} before it ended: "
                "what it would have shown after that is missing",
                cause="interrupted",
            )
        elif kind == "server_failed" and stopped is not None:
            # After the stop: the server was killed by it, or its connection closed by it —
            # the stop's doing, not the server's, and already said by run_stopped.
            continue
        elif kind == "server_failed":
            # Nothing the scenario asks about was observed: every zero below is "not looked
            # at", and a run like that is never one that found nothing.
            detail = event.get("detail")
            verdict.add(
                SERVER_FAILED,
                f"server_failed: {event.get('reason')}" + (f" ({detail})" if detail else ""),
                cause=_http_cause(event.get("reason"), "server_failed"),
            )
        elif kind == "sandbox_failed":
            # Before the target the server cannot have caused it: it did not exist yet. Any
            # other phase, named or not, it can have — and then the run stays in the worst case.
            before = event.get("phase") == "before_target"
            verdict.add(
                SANDBOX_FAILED,
                f"sandbox_failed: {event.get('condition')} ({event.get('phase')})",
                cause="sandbox_failed" if before else "sandbox_failed_after_target",
            )
        elif kind == "egress_summary":
            egress = event
        elif kind == "sandbox_step" and event.get("step") == "images" and event.get("ok"):
            images = event.get("detail")
        elif kind == "server_exited":
            verdict.server_exit = {
                "exit_code": event.get("exit_code"),
                "signal": event.get("signal"),
            }
        elif kind in ("step_skipped", "step_unanswered"):
            skipped_for_it = skipped_for_it or (
                kind == "step_skipped" and event.get("reason") == OBSERVATION_REJECTED
            )
            _step(event, verdict, observed=_observed(started))
        elif kind == "token_observation":
            refusal = refusal or _refusal(event)
        elif kind == "call_failed":
            _call_failed(event, verdict)
        elif kind == "script_finished":
            script_end = event
        elif kind == "limit_exceeded" and event.get("limit") == "client_settle_seconds":
            unsettled = event
        elif kind == "recording_stopped":
            verdict.add(
                INCOMPLETE,
                f"the recording stopped at seq {event.get('from_seq')} ({event.get('reason')}): "
                "everything after it is missing",
                cause="recording_stopped",
            )
    if (
        started is not None
        and started.get("transport") == TRANSPORT_HTTP
        and finished is not None
        and not _http_counts(finished.get("http"))
    ):
        verdict.add(
            INCOMPLETE,
            "run_finished of an HTTP run has no counts of what was forwarded: what the bodies "
            "carried cannot be checked against what the recording holds",
            cause="http_counts_missing",
        )
    if started is not None:
        _isolation(started, egress, verdict)
        _environment(started, images, verdict)
        if started.get("mode") == "driver" and script_end is None:
            verdict.add(
                INCOMPLETE,
                "no script_finished: the script did not reach its end, the inventory may "
                "be partial"
                + (
                    f" (the closing event stopped waiting for it after {unsettled.get('value')} "
                    "s, client_settle_seconds)"
                    if unsettled is not None
                    else ""
                ),
                cause="no_script_finished",
            )
    if undecodable:
        verdict.add(
            INCOMPLETE,
            f"{undecodable} server message(s) were not valid UTF-8: read as a client decodes "
            "them, not as they were sent",
            cause="message_undecodable",
        )
    _undecodable_client(undecodable_client, finished, verdict)
    refused = _observed(started) and refusal and skipped_for_it
    verdict.refused = bool(refused and finished is not None)
    _completeness(
        finished,
        recorded,
        cut,
        verdict,
        stopped=stopped is not None,
        refused=refused,
    )
    return verdict


def _undecodable_client(marked: int, finished: dict[str, Any] | None, verdict: Verdict) -> None:
    """Client messages that were not valid UTF-8: the run is not a result, for a cause that is
    the client's and not the server's.

    Two witnesses to the same messages: the recorder's ``not_utf8`` on each message event, and
    the inspector's count in ``run_finished``, which survives a message event dropped from a
    full queue. The larger says how many. A recording without the count reads 0; a count that
    is not a count is not taken for 0.
    """
    counted = finished.get("client_undecodable", 0) if isinstance(finished, dict) else 0
    if isinstance(counted, bool) or not isinstance(counted, int) or counted < 0:
        verdict.add(
            INCOMPLETE,
            f"run_finished's client_undecodable is not a count ({counted!r})",
            cause="client_message_undecodable",
        )
        return
    if max(marked, counted):
        verdict.add(
            INCOMPLETE,
            f"{max(marked, counted)} client message(s) were not valid UTF-8: the client's doing, "
            "not held against the server",
            cause="client_message_undecodable",
        )


def _capped(event: dict[str, Any], cut: dict[tuple[str, str], int], verdict: Verdict) -> None:
    """A message cut at the per-message cap: what it cut is counted as accounted for, and the
    cap is kept as a truncation with the true numbers."""
    named = event.get("cut")
    if not isinstance(named, dict):
        verdict.add(
            INCOMPLETE,
            f"findings_capped seq={event.get('seq')}: no cut to account for",
            cause="cap_unaccounted",
        )
        return
    for statement, signals in named.items():
        if not isinstance(signals, dict):
            continue
        for signal, count in signals.items():
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                cut[(statement, signal)] = cut.get((statement, signal), 0) + count
    verdict.truncations.append(
        {
            "kind": "findings_per_message",
            "message_seq": event.get("message_seq"),
            "method": event.get("method"),
            "cap": event.get("cap"),
            "made": event.get("made"),
            "recorded": event.get("recorded"),
            "cut": named,
        }
    )


def _observed(started: dict[str, Any] | None) -> bool:
    """Whether the run is a token observation: ``run_started.auth.observation`` names one."""
    auth = started.get("auth") if started is not None else None
    return isinstance(auth, dict) and auth.get("observation") in TOKEN_OBSERVATIONS


def _refusal(event: dict[str, Any]) -> bool:
    """Whether ``token_observation`` has an exchange the endpoint turned away with 401 or 403."""
    exchanges = event.get("exchanges")
    return isinstance(exchanges, list) and any(
        isinstance(exchange, dict)
        and exchange.get("accepted") is False
        and exchange.get("http_status") in (401, 403)
        for exchange in exchanges
    )


def _step(event: dict[str, Any], verdict: Verdict, *, observed: bool = False) -> None:
    """A step that was not sent, or not answered in full: a gap in the inventory, a recorded
    cap, or something the server said about itself (a capability it does not offer). The steps
    a token observation did not send because the server turned it away are none of these
    (rule 14); in a run that is no observation the same word is a step that was not sent."""
    step, reason = event.get("step"), event.get("reason")
    if observed and event.get("type") == "step_skipped" and reason == OBSERVATION_REJECTED:
        return
    if event.get("type") == "step_unanswered" and step == "tools/call" and reason == UNREADABLE:
        # The server decides how large and how deep its answer is: what it delivered was not
        # read, and is named for what it was, not as an answer that never came.
        verdict.add(
            INCOMPLETE,
            f"the answer to a tool call could not be read ({reason}): what it delivered was "
            "not inspected",
            cause="call_result_unreadable",
        )
    elif event.get("type") == "step_unanswered":
        verdict.add(
            INCOMPLETE,
            f"step {step} unanswered after {event.get('pages')} page(s) ({reason}): "
            "the inventory is partial",
            cause=_http_cause(reason, "step_unanswered"),
        )
    elif not isinstance(reason, str) or reason in PARTIAL_REASONS or reason == TOOL_NOT_LISTED:
        # A reason that is no string (a damaged or foreign recording) does not say the step
        # was left out on purpose: the step was not sent, and the inventory is partial.
        verdict.add(
            INCOMPLETE,
            f"step {step} not sent ({reason}): the inventory is partial",
            cause="step_not_sent",
        )
    elif reason == PAGE_LIMIT:
        verdict.truncations.append(
            {"kind": "page_limit", "step": step, "pages": event.get("detail")}
        )


def _call_failed(event: dict[str, Any], verdict: Verdict) -> None:
    """A tool call the server answered with an error: the run's own state, named by the kind.
    A record that names no tool or no kind this tool writes says nothing that can be trusted
    about the call, and the run is incomplete for it — never complete by default."""
    tool, kind, code = event.get("tool"), event.get("kind"), event.get("code")
    if not isinstance(tool, str) or kind not in CALL_FAILURES:
        verdict.add(
            INCOMPLETE,
            f"a call_failed record that is not one (tool {tool!r}, kind {kind!r})",
            cause="call_record_unreadable",
        )
        return
    if kind == CALL_RPC_ERROR:
        said = f"a JSON-RPC error{'' if not isinstance(code, int) else f' ({code})'}"
        cause = "call_error"
    else:
        said, cause = "a result that says isError", "tool_error"
    verdict.add(
        CALL_FAILED,
        f"the call of tool {tool} was answered with {said}: the server answered, and the "
        "content the call was to deliver did not come",
        cause=cause,
    )


def _http_counts(value: Any) -> bool:
    """Whether ``run_finished.http`` is an account at all: a mapping with every count in it,
    each a count — a whole number not below 0, ``responses`` a mapping of such numbers by
    class. An empty or partial one, or one of other values, says nothing about what was
    forwarded. Whether the counts agree with the ``http_*`` events is not checked here."""
    if not isinstance(value, dict) or not all(key in value for key in HTTP_COUNTS):
        return False
    responses = value["responses"]
    numbers = [value[key] for key in HTTP_COUNTS if key != "responses"]
    if not isinstance(responses, dict):
        return False
    return all(_count(number) for number in [*numbers, *responses.values()])


def _count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _http_cause(reason: Any, otherwise: str) -> str:
    """The cause a reason only HTTP knows names, else ``otherwise``. A reason that is not a
    string (a damaged or foreign recording) names nothing of its own and is judged as before."""
    return HTTP_CAUSES.get(reason, otherwise) if isinstance(reason, str) else otherwise


def _tally(event: dict[str, Any]) -> tuple[str, str] | None:
    key = event.get("key")
    if not isinstance(key, dict):
        return None
    statement, signal = key.get("statement"), key.get("signal")
    if not isinstance(statement, str) or not isinstance(signal, str):
        return None
    return statement, signal


def _isolation(started: dict[str, Any], egress: dict[str, Any] | None, verdict: Verdict) -> None:
    """A sandboxed run carries the account of its target's egress, and that account holds.

    A run without it — the sandbox's own summary lost, or a recording that claims an isolation
    it has no evidence of — is missing data: what the target sent is then unknown, not
    "nothing". An account that does not hold is the observation failing. An account that holds
    but lacks datagrams the kernel counted is missing data again (:data:`UDP_LOSS_LIMIT`).
    """
    isolation = started.get("isolation", "host")
    if isolation not in ISOLATIONS:
        verdict.add(
            INCOMPLETE,
            f"run_started names an isolation this tool does not know: {isolation!r}",
            cause="unknown_isolation",
        )
        return
    if isolation not in OBSERVED_ISOLATIONS:
        return
    if egress is None:
        verdict.add(
            INCOMPLETE,
            f"{isolation} run without egress_summary: the target's egress is unknown",
            cause="no_egress_summary",
        )
    else:
        if egress.get("consistent") is not True:
            verdict.add(
                SANDBOX_FAILED,
                "egress_summary: the sink's account differs from the kernel's",
                cause="egress_inconsistent",
            )
        _udp_loss(egress.get("udp_loss"), verdict)


def _udp_loss(loss: Any, verdict: Verdict) -> None:
    """Whether the sink received every UDP datagram the kernel counted, by the numbers the
    sandbox recorded — the rate is worked out here from them, never taken from the file."""
    loss = loss if isinstance(loss, dict) else {}
    numbers = loss.get("kernel"), loss.get("lost")
    if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in numbers):
        verdict.add(
            INCOMPLETE,
            "egress_summary has no udp_loss: what the sink missed is unknown",
            cause="udp_loss_unknown",
        )
        return
    kernel, lost = numbers
    if lost > kernel:
        verdict.add(
            INCOMPLETE,
            f"udp_loss: {lost} lost of {kernel} counted is not an account",
            cause="udp_loss_unknown",
        )
        return
    rate = lost / kernel if kernel else 0.0
    if rate > UDP_LOSS_LIMIT:
        unseen = loss.get("unseen_destinations")
        verdict.add(
            INCOMPLETE,
            f"the sink missed {lost} of {kernel} UDP datagram(s) ({rate:.2%})"
            + (f", {unseen} destination(s) not once" if unseen else "")
            + ": what they carried was not observed",
            cause="udp_loss",
        )


def _environment(started: dict[str, Any], images: Any, verdict: Verdict) -> None:
    """A sandboxed run ran the images its environment names — by id, as the sandbox's own
    first step recorded them. Otherwise the run observed in another environment than the one
    it is compared under, and its observation is not the one it claims."""
    env = (started.get("reproduction") or {}).get("environment")
    if not isinstance(env, dict) or started.get("isolation") not in OBSERVED_ISOLATIONS:
        return
    if not isinstance(images, dict):
        return  # the sandbox never got as far as its images; it says so itself
    ran = images.get("images") or {}
    for role, name in (("sandbox", "sandbox_image"), ("target", "target_image")):
        if (ran.get(role) or {}).get("id") != env.get(name):
            verdict.add(
                SANDBOX_FAILED,
                f"the {role} image that ran is not the one the environment names "
                f"({(ran.get(role) or {}).get('id')!r}, not {env.get(name)!r})",
                cause="images_mismatch",
            )


def _silence(
    finished: dict[str, Any],
    verdict: Verdict,
    *,
    stopped: bool = False,
    refused: bool = False,
) -> None:
    """A server that said nothing where it had to is a server that failed (:func:`server_silent`)
    — in proxy mode as in driver mode, with what it ended with in the reason. A session in which
    nobody said anything is incomplete (:func:`empty_session`) — where one took place: a run
    whose server never ran has 0, 0 and no exit, and its graver state says why already. A token
    observation the endpoint refused (``refused``, rule 14) is no silence: a refusal with no
    body byte is its result."""
    output, given = finished.get("server_output_bytes"), finished.get("client_input_bytes")
    first = finished.get("server_exited_first")
    counts = all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in (output, given))
    if not counts or not isinstance(first, bool):
        verdict.add(
            INCOMPLETE,
            "run_finished does not say what the server and the client wrote: whether anything "
            "was observed is unknown",
            cause="server_output_unknown",
        )
        return
    if stopped and not first:
        # The run was stopped before the server ended on its own: whether it would have
        # answered, or anyone would have spoken, is not known. run_stopped says why.
        return
    if empty_session(output, given, first):
        if verdict.server_exit is not None:
            verdict.add(
                INCOMPLETE,
                "empty_session: neither the server nor its client wrote anything, and the client "
                "ended the session: nothing was asked and nothing observed",
                cause="empty_session",
            )
        return
    if refused or not server_silent(output, given, first):
        return
    ended = verdict.server_exit or {}
    how = (
        f"exit code {ended['exit_code']}"
        if ended.get("exit_code") is not None
        else f"signal {ended['signal']}"
        if ended.get("signal") is not None
        else "no exit recorded"
    )
    when = (
        "while its client was still connected"
        if first
        else f"though the client wrote {given} byte(s)"
    )
    verdict.add(
        SERVER_FAILED,
        f"server_silent: the server wrote nothing to its stdout and ended ({how}) {when}: "
        "nothing was observed",
        cause="server_silent",
    )


def _completeness(
    finished: dict[str, Any] | None,
    recorded: dict[tuple[str, str], int],
    cut: dict[tuple[str, str], int],
    verdict: Verdict,
    *,
    stopped: bool = False,
    refused: bool = False,
) -> None:
    """Whether every finding the run made is in the recording or cut at a recorded cap,
    statement by statement. Recorded plus cut must be exactly what was counted."""
    if finished is None:
        verdict.add(
            INCOMPLETE,
            "no run_finished: the recording ends early, findings may be missing",
            cause="no_run_finished",
        )
        return
    verdict.announced_server = server_field(finished.get("announced_server"))
    _silence(finished, verdict, stopped=stopped, refused=refused)
    if finished.get("unwritten_events"):
        verdict.add(
            INCOMPLETE,
            f"{finished['unwritten_events']} event(s) were never written: the recording lacks them",
            cause="unwritten_events",
        )
    if finished.get("inspection_bounded"):
        verdict.add(
            INCOMPLETE,
            f"{finished['inspection_bounded']} message(s) were only partly inspected",
            cause="inspection_bounded",
        )
    counted = finished.get("findings_by_statement")
    if not isinstance(counted, dict):
        verdict.add(
            INCOMPLETE,
            "run_finished has no findings_by_statement to check against",
            cause="counts_missing",
        )
        return
    for statement, signals in sorted(counted.items()):
        if not isinstance(signals, dict):
            verdict.add(
                INCOMPLETE,
                f"run_finished: counts for {statement!r} are not a mapping",
                cause="counts_missing",
            )
            continue
        for signal, made in sorted(signals.items()):
            verdict.statements.add((statement, signal))
            have = recorded.get((statement, signal), 0)
            capped = cut.get((statement, signal), 0)
            if have + capped != made:
                verdict.add(
                    INCOMPLETE,
                    f"statement {statement!r} signal {signal!r}: {made} made, {have} recorded"
                    + (f", {capped} cut at the per-message cap" if capped else ""),
                    cause="findings_missing",
                )
    for statement, signal in sorted(recorded.keys() | cut.keys()):
        if (statement, signal) not in verdict.statements:
            verdict.add(
                INCOMPLETE,
                f"statement {statement!r} signal {signal!r}: recorded but not counted",
                cause="findings_uncounted",
            )
