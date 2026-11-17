"""The answers of two identities side by side: ``engagement compare RUN_A RUN_B``.

Two driver runs of one engagement and one script, made as two identities, are read from their
recordings. Nothing is sent and nothing is written. For each tool call of the script the table
says how each identity was answered (``ok``, ``rpc_error`` with its code, ``http_401``,
``http_403``, ``http_other`` with the status, ``no_answer`` or ``answer_not_linked``), whether the
two answers are the same (``same``, ``different``, or ``not_compared``), and where the first
difference sits. For each list (tools, prompts, resources) it names
what only one of the two sees, where both runs read the list to its end.

**An observation, not a severity.** Nothing here says whether a difference is wanted; that is
the operator's to judge, and the tool has no ground to. There is no severity, no verdict.

**No value from an answer is ever shown.** A difference is located, never quoted: the path of
the first place that differs, written like a locator of the inspector (``paths``) but with every
list item by its index, and the words of the outcome. A key of the answer stands in the path only
if the MCP schema has it (:data:`SCHEMA_KEYS`); any other key, and everything below
``structuredContent``, ``_meta`` and ``error.data``, is ``*``. What is shown besides are
identifiers of the server, the names of what it lists, and they go through the terminal filter of
the caller like every name that comes from the traffic. The one number of an answer that is shown
is the code of a JSON-RPC error, and only a small integer (:data:`CODE_RANGE`).

**Its limit.** It does not guard against a recording edited on purpose (whoever deletes a line
deletes a step too; the digests are for that): it sees to it that an unexpected type never turns
silently into a wrong result.

**The comparison claims no more than both recordings show.** A list is complete in a run only if
its last page was answered without a ``nextCursor``; if either run did not read it to its end
(page limit, a page never answered, a listing that does not follow cursors), nothing is said of
what only one side sees. An answer belongs to its request only if it stands after the request in
the recording (``seq``) and, over HTTP, in the same ``exchange`` or in one that continues it (a
``GET`` with ``Last-Event-ID`` whose value is the ``event_id`` of the last earlier message, which
stands in the exchange continued); of several the first counts. A continuation the recording
does not show (a ``GET`` with a ``Last-Event-ID`` that no earlier message carries, as after a
priming event, which holds an event id and no data and so is not in the recording) cannot be
tied to its request: a message of the server with the id of the request in such a continuation
is not read, the step is ``answer_not_linked`` and the row says ``not_compared``, neither the
same nor different. Comparing is done on the
recording, so on the masked answers.

**What is refused** (:class:`Refused`, one line naming the reason and never a value): runs of
two engagements, or of none; two scripts (two digests, a digest on one run only, or two script
names); one identity twice, or a run without one; pseudonyms that last a run only, which are not
the same value in the other run; a step sent by both that is not the same; a field the alignment
depends on (the authorization, the exchange and status of an HTTP response, the exchange, method
and headers of an HTTP request, the position, direction, method, id and exchange of a message, and
the transport that tells whether a message has an exchange) that is of the wrong type or, for the
id of a message and the exchange of one over HTTP, ``null``. The one ``null`` id that stands is
that of an error of the server (JSON-RPC: a request it could not read); it answers no request.
A message whose direction is neither of the two, whose payload is no object, whose encoding is no
text, or a message of the client sent as JSON whose data is no object (a batch: a run of ``drive``
sends none) is refused too; a message of the server whose data is no object answers no request and
is left out.
A field the comparison can leave out without becoming wrong (an event id, a name, a cursor) counts
as missing. Without a digest on
either side and without two different names, only the tools of the steps both runs sent are
compared.

**A step is a step of the script.** Only the tool calls are steps, numbered in the order of the
script; the handshake, the discovery request and the listings are the driver's and are not
counted (the listings are compared for themselves). The driver records no step number, so the
steps are counted from the recording: each ``tools/call`` it sent, and each one it says it did
not send (``step_skipped``), in the order they stand. After a failure of the driver the recording
holds a ``step_skipped`` for every step of the script, the ones sent included; after a refusal
of the scope guard (a ``call_blocked`` of the driver) only for the refused step and those after it
(see :func:`_read_steps`). A run that ended early, a ``403`` that ends the script say, is not
refused: for the steps it never sent the result is ``not_sent``, with the state and causes of that
run.

A line of the recording that cannot be read (no JSON, nested too deeply, no object) before the last
one that is not empty is refused: a step on it would be lost, and every later one would move up a
number. The last such line may be unreadable (a run cut off while it wrote): nothing moves up
behind it, the run is ``incomplete`` with the cause ``line``, and it is compared.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_kymograph import events as recorded
from mcp_kymograph import verdict

#: The sentence every output carries (docs/engagements.md).
OBSERVATION = "an observation, not a severity"

OK = "ok"
RPC_ERROR = "rpc_error"
HTTP_401 = "http_401"
HTTP_403 = "http_403"
HTTP_OTHER = "http_other"
NO_ANSWER = "no_answer"
#: A message with the id of the request stands only in a continuation the recording does not show.
NOT_LINKED = "answer_not_linked"
NOT_SENT = "not_sent"

SAME = "same"
DIFFERENT = "different"
#: One side has an answer the recording does not tie to its request: nothing to say of the two.
NOT_COMPARED = "not_compared"
#: Neither run sent the step: there is nothing to compare.
NOTHING = "none"

#: The lists compared, by the method that delivers them, the member of the answer that holds the
#: items and the member of an item that names it (``paths.IDENTITY_FIELDS``).
LISTS = {
    "tools": ("tools/list", "tools", "name"),
    "prompts": ("prompts/list", "prompts", "name"),
    "resources": ("resources/list", "resources", "uri"),
}

#: The keys of the MCP schema that may stand in the first path that differs: ``CallToolResult``
#: and its content kinds (text, image, audio, resource_link, embedded resource, annotations), the
#: JSON-RPC error and its envelope, and ``contents``, which belongs to ``ReadResourceResult``.
#: Taken from two revisions of the schema (modelcontextprotocol.io/specification/<revision>/schema):
#: 2025-06-18 has all of them but ``Icon``; 2025-11-25 adds ``Icon``, whence ``icons``, ``src``,
#: ``sizes`` and ``theme``. Any other key is a value of the server.
SCHEMA_KEYS = frozenset(
    {
        "result", "error", "code", "message", "data",
        "content", "structuredContent", "isError", "_meta",
        "type", "text", "mimeType", "annotations", "audience", "priority", "lastModified",
        "uri", "name", "title", "description", "size", "icons", "src", "sizes", "theme",
        "resource", "contents", "blob",
    }
)  # fmt: skip
#: Below these the keys are the server's, whatever they are called (``error.data`` is checked
#: by its place).
OPAQUE_KEYS = frozenset({"structuredContent", "_meta"})

#: The codes of a JSON-RPC error that are shown: the ones JSON-RPC itself assigns and small ones
#: of the server's own. Any other code (and any value that is not an integer) is the server's.
CODE_RANGE = range(-32768, 32768)

#: At most this many names of one side are shown for one list; the rest is counted.
MAX_NAMES = 100

SHOW_LIMIT = 200

Show = Callable[..., str]
#: By id: (seq, exchange, message) of each message of the server that could answer.
Responses = dict[str, list[tuple[int, int | None, dict[str, Any]]]]
#: The exchanges of a ``GET`` that names a ``Last-Event-ID`` no earlier message carries, and those
#: that continue one of these, over any number of continuations.
Unlinked = set[int]
#: By exchange: the exchange it continues. Only the exchanges the recording shows to continue
#: another are in it (see :func:`_continued`).
Resumes = dict[int, int]


CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"
UNREADABLE_MESSAGE = "the recording holds a message this version cannot read"


class Refused(Exception):
    """The two runs are not to be compared. The text names the reason and never a value."""


@dataclass
class Step:
    """One tool call of the script, as a run recorded it."""

    number: int
    tool: str | None
    arguments: str | None
    #: (id key, exchange, seq) of its request; None where the run never sent it.
    request: tuple[str, int | None, int] | None


@dataclass
class Request:
    """A request of the client as the recording holds it."""

    seq: int
    identifier: str
    method: str
    exchange: int | None


@dataclass
class Listing:
    """What a run read of one list: the identifiers its answers named, and whether the last page
    it asked for was answered without a ``nextCursor``."""

    names: set[str] = field(default_factory=set)
    complete: bool = False


@dataclass
class Answer:
    """How one identity was answered to one request."""

    outcome: str
    code: int | None = None
    status: int | None = None
    #: The ``result`` or ``error`` member of the JSON-RPC answer, or None where there is none.
    body: dict[str, Any] | None = None

    #: For ``not_sent``: the state and causes of the run that did not send the step.
    state: str | None = None
    causes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        found: dict[str, Any] = {"result": self.outcome, "code": self.code, "status": self.status}
        if self.outcome == NOT_SENT:
            found.update(state=self.state, causes=self.causes)
        return found

    def words(self) -> str:
        if self.outcome == RPC_ERROR:
            return (
                f"{RPC_ERROR} {self.code}"
                if self.code is not None
                else f"{RPC_ERROR} (code not shown)"
            )
        if self.outcome == HTTP_OTHER and self.status is not None:
            return f"{HTTP_OTHER} {self.status}"
        return self.outcome

    def note(self) -> str:
        """For a step not sent: why, in the words of the run's verdict."""
        causes = f" ({', '.join(self.causes)})" if self.causes else ""
        return f"{self.state}{causes}"


@dataclass
class Run:
    state: str
    causes: list[str]
    identity: str
    role: str | None
    engagement_id: str
    engagement_digest: str
    pseudonyms: str | None
    script_digest: str | None
    script: str | None
    steps: list[Step]
    #: By step number, for the steps the run sent.
    answers: dict[int, Answer]
    listed: dict[str, Listing]

    @property
    def complete(self) -> bool:
        return self.state == verdict.COMPLETE


@dataclass
class CallRow:
    step: int
    tool: str
    a: Answer
    b: Answer
    answers: str
    #: The locator of the first place that differs; "" for the answer as a whole; None if same.
    first_difference: str | None


@dataclass
class ListRow:
    kind: str
    compared: bool
    only_a: list[str]
    only_b: list[str]
    #: Where not compared: which run did not read the list to its end ("incomplete in A").
    reason: str | None = None


@dataclass
class Comparison:
    engagement_id: str
    engagement_digest: str
    a: Run
    b: Run
    calls: list[CallRow]
    lists: list[ListRow]

    @property
    def exit_code(self) -> int:
        return verdict.EXIT_CODES[verdict.gravest([self.a.state, self.b.state])]

    def to_dict(self, show: Show) -> dict[str, Any]:
        def run(held: Run) -> dict[str, Any]:
            return {
                "identity": show(held.identity),
                "role": None if held.role is None else show(held.role),
                "state": held.state,
                "causes": held.causes,
            }

        return {
            "observation": OBSERVATION,
            "engagement": {"id": show(self.engagement_id), "digest": self.engagement_digest},
            "runs": {"a": run(self.a), "b": run(self.b)},
            "calls": [
                {
                    "step": row.step,
                    "tool": show(row.tool),
                    "a": row.a.to_dict(),
                    "b": row.b.to_dict(),
                    "answers": row.answers,
                    "first_difference": None
                    if row.first_difference is None
                    else show(row.first_difference, limit=SHOW_LIMIT),
                }
                for row in self.calls
            ],
            "lists": {
                row.kind: {
                    "compared": row.compared,
                    "reason": row.reason,
                    "only_a": [show(name) for name in row.only_a[:MAX_NAMES]],
                    "only_a_count": len(row.only_a),
                    "only_b": [show(name) for name in row.only_b[:MAX_NAMES]],
                    "only_b_count": len(row.only_b),
                }
                for row in self.lists
            },
        }

    def render(self, show: Show) -> str:
        lines = []
        for label, held in (("A", self.a), ("B", self.b)):
            note = "" if held.complete else f" [{', '.join(held.causes)}]: not a result"
            lines.append(f"run {label}: {held.state}{note}")
        lines.append(f"engagement: {show(self.engagement_id)}")
        for label, held in (("A", self.a), ("B", self.b)):
            role = "" if held.role is None else f", role {show(held.role)}"
            lines.append(f"identity {label}: {show(held.identity)}{role}")
        lines.append(f"This is {OBSERVATION}.")
        lines.append("")
        if self.calls:
            lines.append(
                f"{'step':<5} {'tool':<24} {'A':<18} {'B':<18} {'answers':<12} first difference"
            )
            for row in self.calls:
                where = ""
                if row.first_difference is not None:
                    where = (
                        show(row.first_difference, limit=SHOW_LIMIT) or "(the answer as a whole)"
                    )
                unsent = [
                    f"run {label} did not send it: {answer.note()}"
                    for label, answer in (("A", row.a), ("B", row.b))
                    if answer.outcome == NOT_SENT
                ]
                if unsent:
                    where = "; ".join(unsent)
                lines.append(
                    f"{row.step:<5} {show(row.tool, limit=24):<24} {row.a.words():<18} "
                    f"{row.b.words():<18} {row.answers:<12} {where}".rstrip()
                )
        else:
            lines.append("no tool call in the script")
        for row in self.lists:
            lines.append("")
            if not row.compared:
                lines.append(f"{row.kind}: not compared: {row.reason}")
                continue
            for label, names in (("A", row.only_a), ("B", row.only_b)):
                shown = ", ".join(show(name) for name in names[:MAX_NAMES]) or "none"
                more = f" and {len(names) - MAX_NAMES} more" if len(names) > MAX_NAMES else ""
                lines.append(f"{row.kind} only {label} sees: {shown}{more}")
        return "\n".join(lines) + "\n"


# -- reading a run ------------------------------------------------------------------------


def load(path: Path, label: str) -> Run:
    """One run read from its recording (``events.jsonl`` or its directory), or :class:`Refused`."""
    where = path / "events.jsonl" if path.is_dir() else path
    try:
        raw = where.read_bytes()
    except OSError:
        raise Refused(f"run {label} cannot be read") from None
    events, problems = verdict.read_events(raw)
    started = events[0] if events and events[0].get("type") == "run_started" else None
    if started is None or verdict.schema_problem(events) is not None:
        raise Refused(f"run {label} is not a recording this version reads")
    if started.get("mode") != "driver":
        raise Refused(f"run {label} is not a driver run: there is no script to align")
    if problems and _unreadable_before_the_end(raw):
        raise Refused(
            f"run {label} holds a line this version cannot read, before its end: "
            "the steps after it could not be counted"
        )
    judged = verdict.judge(events, problems)
    auth = started.get("auth")
    identity = auth.get("identity") if isinstance(auth, dict) else None
    if not isinstance(identity, str):
        raise Refused(f"run {label} has no identity")
    role = auth.get("role")
    authorization = started.get("authorization")
    if authorization is not None and not isinstance(authorization, dict):
        raise Refused(f"run {label} has an authorization this version cannot read")
    held = (authorization or {}).get("engagement")
    held = held if isinstance(held, dict) else {}
    engagement_id, engagement_digest = (
        held.get("engagement_id_declared"),
        held.get("engagement_digest"),
    )
    if not (isinstance(engagement_id, str) and isinstance(engagement_digest, str)):
        raise Refused(f"run {label} was made under no engagement")
    try:
        steps, answers, listed = _read_steps(events)
    except Refused as refusal:
        raise Refused(f"run {label}: {refusal}") from None
    digest = started.get("script_digest")
    script = started.get("script")
    return Run(
        state=judged.state,
        causes=judged.causes,
        identity=identity,
        role=role if isinstance(role, str) else None,
        engagement_id=engagement_id,
        engagement_digest=engagement_digest,
        pseudonyms=started.get("pseudonyms"),
        script_digest=digest if isinstance(digest, str) else None,
        script=script if isinstance(script, str) else None,
        steps=steps,
        answers=answers,
        listed=listed,
    )


def _unreadable_before_the_end(raw: bytes) -> bool:
    """Whether a line other than the last one that is not empty cannot be read. That one may be
    cut off by a run that stopped in the middle of writing: nothing moves up behind it. Without
    it the recording reads without a problem, or the problem was elsewhere."""
    lines = raw.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    return bool(lines) and bool(verdict.read_events(b"\n".join(lines[:-1]))[1])


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _key(identifier: Any) -> str | None:
    if isinstance(identifier, bool) or not isinstance(identifier, (str, int)):
        return None
    return _canonical(identifier)


def _read_steps(
    events: list[dict[str, Any]],
) -> tuple[list[Step], dict[int, Answer], dict[str, Listing]]:
    steps: list[Step] = []
    statuses: dict[int, int] = {}
    requests: list[Request] = []
    responses: Responses = {}
    resumes: Resumes = {}
    unlinked: Unlinked = set()
    # The exchange of the last message so far for each event id, as the recording holds the id.
    last_event: dict[str, int] = {}
    # Two ways write a step_skipped with driver_error. Driver.run calls
    # _skip_remaining(self._script.steps, DRIVER_ERROR) when the driver fails: all steps of the
    # script, those already sent too. These entries are the script's length, not further steps;
    # the steps they stand for and that were not seen get their numbers below. Driver._call ->
    # _refuse writes call_blocked (where: BLOCKED_BY_DRIVER) and then driver_error for the
    # refused step and those after it only (_skip_remaining(steps[index + 1:], ...)): each of
    # those is a step of its own, none of the sent ones among them. ``refused`` says the second.
    whole_script = 0
    refused = False
    # A wait for a ``Retry-After`` (``paced``) keeps a step one step. The driver then sends the same
    # request again, with its id, or writes that it did not go on (``step_skipped``). ``call`` is
    # the id of the ``tools/call`` that was the last request so far, ``waited`` that id after such
    # a wait, until the next request or skipped step says what became of it.
    call: str | None = None
    waited: str | None = None
    transport = events[0].get("transport") if events else None
    for event in events:
        kind = event.get("type")
        if kind == "paced" and event.get("why") == "retry_after":
            waited = call
        if kind == "http_response":
            # The status is the result of the call that travelled in the exchange: without
            # both, a 403 could be lost, and the step would read as answered.
            if not (_is_int(event.get("status")) and _is_int(event.get("exchange"))):
                raise Refused("the recording holds an HTTP response this version cannot read")
            statuses[event["exchange"]] = event["status"]
        if kind == "call_blocked" and event.get("where") == recorded.BLOCKED_BY_DRIVER:
            refused = True
        stopped_in_the_wait = False
        if kind in ("step_skipped", "step_unanswered"):
            # Only a halt in the wait is about the step waited for. A wait that left no time ends
            # in ``step_unanswered``: the step stands as answered, and what is skipped after it
            # are the next steps.
            stopped_in_the_wait = (
                waited is not None
                and kind == "step_skipped"
                and event.get("reason") == recorded.RUN_HALTED
            )
            waited = None
        if kind == "step_skipped" and event.get("step") == "tools/call":
            if event.get("reason") == recorded.DRIVER_ERROR and not refused:
                whole_script += 1
                continue
            if stopped_in_the_wait:
                # The step it was waiting to send again is not sent, and it stays one step.
                steps[-1] = Step(steps[-1].number, None, None, None)
                continue
            # The driver says it did not send this step of the script: it holds the number.
            steps.append(Step(len(steps) + 1, None, None, None))
        if kind == "http_request":
            if not (
                _is_int(event.get("exchange"))
                and isinstance(event.get("method"), str)
                and isinstance(event.get("headers"), dict)
            ):
                raise Refused("the recording holds an HTTP request this version cannot read")
            continued = _continued(event, last_event)
            if continued is not None:
                resumes[event["exchange"]] = continued
                # What continues a continuation the recording does not show is not shown either.
                if continued in unlinked:
                    unlinked.add(event["exchange"])
            elif _resumption(event) is not None:
                unlinked.add(event["exchange"])
        if kind != "message":
            continue
        # Every message has a direction, a payload and an encoding: a message that has none of
        # them cannot be told for a request of the client, and would drop a step.
        direction = event.get("direction")
        payload = event.get("payload")
        if direction not in (CLIENT_TO_SERVER, SERVER_TO_CLIENT):
            raise Refused(UNREADABLE_MESSAGE)
        if not isinstance(payload, dict) or not isinstance(payload.get("encoding"), str):
            raise Refused(UNREADABLE_MESSAGE)
        _note_event_id(event, last_event)
        if payload["encoding"] != "json":
            continue
        data = payload.get("data")
        seq = event.get("seq")
        if not isinstance(data, dict):
            # A request of the client that is not an object (a batch, say) is a step this reading
            # would lose; a message of the server of that kind answers no request, so it drops none.
            if direction == CLIENT_TO_SERVER:
                raise Refused(UNREADABLE_MESSAGE)
            continue
        # The method and the id decide which message is a step and which answers it: of the wrong
        # type either would drop the message and move the steps after it. A request without an id
        # is no step; an id that is there and cannot be a key (null, a fraction, a bool, a list,
        # an object) is not the same as none.
        if "method" in data and not isinstance(data["method"], str):
            raise Refused(UNREADABLE_MESSAGE)
        if "id" not in data:
            continue
        identifier = _key(data["id"])
        if identifier is None:
            # JSON-RPC: a server answers a request it could not read with an error and ``"id":
            # null``. It answers no request of the script, so it drops no step and is left out.
            if direction == SERVER_TO_CLIENT and data["id"] is None and "error" in data:
                continue
            raise Refused(UNREADABLE_MESSAGE)
        # A message with an id takes part in the alignment: a position or an exchange that is
        # not readable would drop a step, or tie an answer to the wrong request. Over stdio there
        # is no exchange (None); over HTTP there is always one, and a missing one would lose a 403.
        exchange = event.get("exchange")
        if transport == recorded.TRANSPORT_STDIO:
            readable = exchange is None or _is_int(exchange)
        else:
            readable = transport == recorded.TRANSPORT_HTTP and _is_int(exchange)
        if not (_is_int(seq) and readable):
            raise Refused(UNREADABLE_MESSAGE)
        if direction == CLIENT_TO_SERVER and isinstance(data.get("method"), str):
            requests.append(Request(seq, identifier, data["method"], exchange))
            if data["method"] == "tools/call":
                if waited == identifier:
                    # The same request after the wait: the last answer is the step's.
                    steps[-1] = _call(steps[-1].number, data, identifier, exchange, seq)
                else:
                    steps.append(_call(len(steps) + 1, data, identifier, exchange, seq))
                call = identifier
            else:
                call = None
            waited = None
        elif direction == SERVER_TO_CLIENT and ("result" in data or "error" in data):
            responses.setdefault(identifier, []).append((seq, exchange, data))
    while len(steps) < whole_script:
        steps.append(Step(len(steps) + 1, None, None, None))
    answers: dict[int, Answer] = {}
    for step in steps:
        if step.request is not None:
            identifier, exchange, seq = step.request
            request = Request(seq, identifier, "tools/call", exchange)
            reply = _reply(request, responses, resumes)
            lost = reply is None and _unlinked_reply(request, responses, unlinked)
            answers[step.number] = _answer(statuses.get(exchange), reply, lost)
    return steps, answers, _lists(requests, responses, resumes)


def _note_event_id(event: dict[str, Any], last_event: dict[str, int]) -> None:
    """Remember the exchange of a message of the server that carries an SSE event id."""
    event_id, exchange = event.get("event_id"), event.get("exchange")
    if (
        event.get("direction") != "server_to_client"
        or not event_id
        or not isinstance(event_id, str)
    ):
        return
    if isinstance(exchange, int) and not isinstance(exchange, bool):
        last_event[event_id] = exchange


def _resumption(event: dict[str, Any]) -> str | None:
    """The ``Last-Event-ID`` of an ``http_request`` that is a ``GET`` with exactly one such header
    that is a non-empty string; None otherwise. The name may be in any case."""
    exchange, headers = event.get("exchange"), event.get("headers")
    if event.get("method") != "GET" or not isinstance(headers, dict):
        return None
    if isinstance(exchange, bool) or not isinstance(exchange, int):
        return None
    given = [value for name, value in headers.items() if str(name).lower() == "last-event-id"]
    if len(given) != 1 or not isinstance(given[0], str) or not given[0]:
        return None
    return given[0]


def _continued(event: dict[str, Any], last_event: dict[str, int]) -> int | None:
    """The exchange an ``http_request`` continues: it is a ``GET`` whose ``Last-Event-ID`` is the
    ``event_id`` of the last earlier message, and that message stands in the exchange continued.
    None where the recording does not show it (no header, one that is not a single value, no
    earlier message with that id). The values are compared as recorded."""
    given = _resumption(event)
    return None if given is None else last_event.get(given)


def _continues(exchange: int | None, origin: int, resumes: Resumes) -> bool:
    """Whether ``exchange`` is ``origin`` or continues it, over any number of continuations."""
    seen = set()
    while exchange is not None and exchange not in seen:
        if exchange == origin:
            return True
        seen.add(exchange)
        exchange = resumes.get(exchange)
    return False


def _reply(request: Request, responses: Responses, resumes: Resumes) -> dict[str, Any] | None:
    """The message of the server that answers a request: with its id, after it in the recording
    and, where the request travelled in an HTTP exchange, in that exchange or in one that
    continues it. The first counts."""
    found = [
        (seq, data)
        for seq, exchange, data in responses.get(request.identifier, [])
        if seq > request.seq
        and (request.exchange is None or _continues(exchange, request.exchange, resumes))
    ]
    return min(found, key=lambda item: item[0])[1] if found else None


def _unlinked_reply(request: Request, responses: Responses, unlinked: Unlinked) -> bool:
    """Whether a message of the server with the id of the request stands after it in a
    continuation the recording does not show. Only that it stands there: nothing of it is read."""
    return any(
        seq > request.seq and exchange in unlinked
        for seq, exchange, _ in responses.get(request.identifier, [])
    )


def _call(number: int, data: dict, identifier: str, exchange: int | None, seq: int) -> Step:
    params = data.get("params")
    params = params if isinstance(params, dict) else {}
    tool = params.get("name")
    tool = tool if isinstance(tool, str) else ""
    return Step(number, tool, _canonical(params.get("arguments")), (identifier, exchange, seq))


def _answer(status: int | None, response: dict[str, Any] | None, unlinked: bool) -> Answer:
    if status == 401:
        return Answer(HTTP_401, status=status)
    if status == 403:
        return Answer(HTTP_403, status=status)
    if status is not None and not 200 <= status < 300:
        return Answer(HTTP_OTHER, status=status)
    if response is None:
        return Answer(NOT_LINKED if unlinked else NO_ANSWER, status=status)
    if "error" in response:
        error = response["error"]
        code = error.get("code") if isinstance(error, dict) else None
        shown = isinstance(code, int) and not isinstance(code, bool) and code in CODE_RANGE
        return Answer(RPC_ERROR, code=code if shown else None, status=status, body={"error": error})
    return Answer(OK, status=status, body={"result": response.get("result")})


def _lists(requests: list[Request], responses: Responses, resumes: Resumes) -> dict[str, Listing]:
    """Per list: the names of every page answered, and complete only if the last page asked for
    was answered without a ``nextCursor``."""
    found: dict[str, Listing] = {kind: Listing() for kind in LISTS}
    for kind, (method, member, field_name) in LISTS.items():
        asked = sorted((r for r in requests if r.method == method), key=lambda r: r.seq)
        for position, request in enumerate(asked):
            reply = _reply(request, responses, resumes)
            result = reply.get("result") if reply is not None else None
            items = result.get(member) if isinstance(result, dict) else None
            if not isinstance(items, list):
                continue
            for item in items:
                name = item.get(field_name) if isinstance(item, dict) else None
                if isinstance(name, str):
                    found[kind].names.add(name)
            if position == len(asked) - 1:
                found[kind].complete = result.get("nextCursor") is None
    return found


# -- comparing ----------------------------------------------------------------------------


def compare(a: Run, b: Run) -> Comparison:
    """The two runs side by side, or :class:`Refused`."""
    if (a.engagement_id, a.engagement_digest) != (b.engagement_id, b.engagement_digest):
        raise Refused("the runs are not of the same engagement")
    if a.identity == b.identity:
        raise Refused("both runs are of the same identity")
    for label, held in (("A", a), ("B", b)):
        if held.pseudonyms != "per_engagement":
            raise Refused(
                f"run {label} has pseudonyms that last a run only: "
                "two runs do not share them, so what they hide cannot be compared"
            )
    _same_script(a, b)
    calls = []
    for number in range(1, max(len(a.steps), len(b.steps)) + 1):
        one = a.steps[number - 1] if number <= len(a.steps) else None
        other = b.steps[number - 1] if number <= len(b.steps) else None
        sent = [step for step in (one, other) if step is not None and step.request is not None]
        if len(sent) == 2:
            if one.tool != other.tool:
                raise Refused(f"step {number}: the tool is not the same in both runs")
            if one.arguments != other.arguments:
                raise Refused(f"step {number}: the arguments are not the same in both runs")
        tool = sent[0].tool if sent else ""
        calls.append(_row(number, tool or "", _held(a, one), _held(b, other)))
    return Comparison(a.engagement_id, a.engagement_digest, a, b, calls, _list_rows(a, b))


def _held(run: Run, step: Step | None) -> Answer:
    """The answer a run got to a step, or ``not_sent`` with the state and causes of the run."""
    if step is None or step.request is None:
        return Answer(NOT_SENT, state=run.state, causes=run.causes)
    return run.answers[step.number]


def _same_script(a: Run, b: Run) -> None:
    different = "the runs are of different scripts"
    if a.script is not None and b.script is not None and a.script != b.script:
        raise Refused(different)
    if (a.script_digest is None) != (b.script_digest is None):
        # One run has a digest and the other has none (it ran a built-in script, say).
        raise Refused(different)
    if a.script_digest is not None:
        if a.script_digest != b.script_digest:
            raise Refused(different)
    else:
        # No digest on either side: only the tools of the steps both sent can be told apart.
        for one, other in zip(a.steps, b.steps, strict=False):
            if one.request and other.request and one.tool != other.tool:
                raise Refused(f"{different}: the steps differ in the tool")


def _row(number: int, tool: str, a: Answer, b: Answer) -> CallRow:
    # An answer the recording does not tie to its request says nothing of the two, whatever the
    # other side is, a step not sent included.
    if NOT_LINKED in (a.outcome, b.outcome):
        return CallRow(number, tool, a, b, NOT_COMPARED, None)
    if NOT_SENT in (a.outcome, b.outcome):
        either = a.outcome == b.outcome
        return CallRow(number, tool, a, b, NOTHING if either else DIFFERENT, None if either else "")
    where = _first(a.body, b.body, _Trail(""))
    same = where is None and (a.outcome, a.code, a.status) == (b.outcome, b.code, b.status)
    if same:
        return CallRow(number, tool, a, b, SAME, None)
    return CallRow(number, tool, a, b, DIFFERENT, where or "")


@dataclass(frozen=True, slots=True)
class _Trail:
    """The locator so far, and whether what is below is the server's to name."""

    located: str
    opaque: bool = False

    def key(self, name: str) -> _Trail:
        """A key stands in the path only if the schema has it and it is not below a place whose
        keys are the server's; any other is ``*``, and so is everything below it."""
        known = not self.opaque and name in SCHEMA_KEYS
        step = name if known else "*"
        opaque = not known or name in OPAQUE_KEYS or (name == "data" and self.located == "error")
        return _Trail(f"{self.located}.{step}" if self.located else step, opaque)

    def element(self, position: int) -> _Trail:
        # Always the index: a selector of paths.IDENTITY_FIELDS would be a value of the server.
        return _Trail(f"{self.located}[{position}]", self.opaque)


def _first(a: Any, b: Any, trail: _Trail) -> str | None:
    """The locator of the first place two documents differ — keys in sorted order, list items in
    their order — or None where their canonical JSON is the same. Never a value."""
    if _canonical(a) == _canonical(b):
        return None
    if isinstance(a, dict) and isinstance(b, dict):
        for name in sorted({*a, *b}, key=str):
            below = trail.key(str(name))
            if name not in a or name not in b:
                return below.located
            found = _first(a[name], b[name], below)
            if found is not None:
                return found
        return trail.located
    if isinstance(a, list) and isinstance(b, list):
        for position, (left, right) in enumerate(zip(a, b, strict=False)):
            found = _first(left, right, trail.element(position))
            if found is not None:
                return found
    return trail.located


def _list_rows(a: Run, b: Run) -> list[ListRow]:
    rows = []
    for kind in LISTS:
        one, other = a.listed[kind], b.listed[kind]
        if not (one.complete and other.complete):
            # A list not read to its end shows nothing of what the other side sees beyond it.
            where = {(False, True): "A", (True, False): "B"}.get(
                (one.complete, other.complete), "both"
            )
            rows.append(ListRow(kind, False, [], [], f"incomplete in {where}"))
        else:
            rows.append(
                ListRow(
                    kind, True, sorted(one.names - other.names), sorted(other.names - one.names)
                )
            )
    return rows
