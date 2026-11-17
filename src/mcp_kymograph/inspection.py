"""The observation inspector: what the server sends that a model could read as instruction.

This is **not a rule**. It changes nothing, decides nothing and judges nothing. It reads the
copy of the traffic that the observer already takes and writes down *where* content appeared
that is addressed at a model rather than at a person. What the built-in walk sees is an
observation; what a scenario statement sees is a finding (below). Neither carries a severity
or a verdict. Whether such content matters depends on what the
consuming side does with it, and that is not visible on the wire.

**It runs on the observer path, which is the original traffic by construction.** The pumps
hand the observer the bytes that came off the wire, before the engine has decided anything
(``Proxy._forward_intercepted`` feeds ``original``), so a poisoned description this tool
injected itself can never reach the inspector. That is the answer to "whose content is
this": structural, not a convention, and pinned by a test rather than by a provenance field
that would always read the same.

**Surfaces are scoped to the method.** A tool description and a fetched document are not the
same kind of text, and a signal that is damning in the first is noise in the second: an
HTML comment in a tool description has no reader but a model, an HTML comment in a document
a tool returned is just HTML. :data:`METADATA_SURFACES` marks the ones that are documentation
written by the server about itself; the rest are content it carried. Each signal declares
how far the walk takes it (:class:`mcp_kymograph.signals.Reach`).

**Responses carry only an id.** Which method a response answers is learned from the request
in the opposite direction, the same correlation the engine makes, in a bounded table per
direction: a request the server sends never stands in for one the client sent under the same id.
Ids are compared as the clients compare them (:mod:`mcp_kymograph.correlation`), so
``1.0`` and ``"1"`` answer request ``1`` here as they do there; an id the clients
would not agree on is reported as a message not inspected in full.

**Two sources of what to look for, two kinds of entry.** The built-in walk visits the surfaces
it knows and applies the walk's signals from :mod:`mcp_kymograph.signals` to every run; what it
sees is an ``observation``. A scenario file can add *statements*: a method, a field path and
the signal IDs to check there. A statement is the operator declaring what counts, so what it
sees is a ``finding`` — a structured entry keyed on server, server version, tool version,
scenario and signal, so that a later run-against-run comparison can tell "new" from
"regressed". Neither carries a severity or a verdict.

A statement reaches places the walk does not (``result.instructions`` in an ``initialize``
answer, say), may name signals the walk never applies, and applies them wherever it points,
whether or not the walk would call that place metadata. **Every statement that applies to a
message leaves a ``statement_evaluated`` record**, including when nothing fired, when its path
was not there and when a work bound stopped it — the reading half has no silent no-op either.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from mcp_kymograph import __version__, correlation, events
from mcp_kymograph.eras import META_SERVER_INFO, PROBE_METHOD
from mcp_kymograph.events import Direction
from mcp_kymograph.paths import resolve
from mcp_kymograph.signals import (
    WALK_CONTENT,
    WALK_METADATA,
    NameIndex,
    Signal,
    Subject,
    Via,
    check,
)

#: A response id maps to at most this many remembered methods before the table is cleared.
#: Mirrors the engine's bound: a server that never answers must not grow it without end.
MAX_TRACKED_IDS = 4096

#: How many observations one message may produce. A hostile ``tools/list`` could otherwise
#: turn one message into thousands of events and push the real traffic out of the queue.
#: The per-method tally in :class:`Inspector` counts the true number, uncapped, so a run
#: summary stays honest about what a capped message actually held — the same split the
#: recorder makes between ``redactions`` and ``redaction_count``.
MAX_OBSERVATIONS_PER_MESSAGE = 20

#: The same cap for findings, kept apart so a busy walk cannot crowd out what a statement
#: was written to see. The per-statement tally counts the true number, and a message that
#: reaches the cap says what it cut, per statement and signal (``findings_capped``): a
#: recorded cap, complete in the sense that what was cut and why is known.
MAX_FINDINGS_PER_MESSAGE = 20

#: How many strings, and how many characters of them, one message is scanned over at all.
#:
#: Two bounds because either can be reached alone: a ``tools/list`` with thousands of tiny
#: schema fields, or one with a few enormous ones. The work is proportional to both, and it
#: runs on the event loop, where time spent holds up *both* directions (the same property
#: ``Engine.modifies`` records for rules). Measured on this machine: a realistic
#: ``tools/list`` costs 0.2 ms, a 64 kB one 26 ms, a 1 MB one 114 ms — of which only 8 ms is
#: parsing and the rest is matching. 256 kB is roughly 30 ms, the same order as the
#: interception overhead measured for the proxy, and far above anything a real
#: server's metadata reaches.
#:
#: A message that reaches either bound is **not fully inspected**, and that is counted:
#: :attr:`Inspector.bounded_messages` reaches ``run_finished``, so a quiet run cannot
#: quietly mean "we stopped looking".
MAX_SCANNED_STRINGS = 2000
MAX_SCANNED_CHARS = 262144

#: How deep the walk follows a tool's schema, in nested objects and lists. JSON Schema nests
#: without limit, and so can a hostile server; a real schema is a handful of levels deep.
#: Deeper than this the walk stops and the message counts as bounded, like one that reaches
#: the work bounds above: followed further, the walk's own recursion would run out (at about
#: a thousand levels, Python's default recursion limit) and take the observer with it.
MAX_SCHEMA_DEPTH = 256

#: How deeply a message from the server may nest at all, counted from its root without
#: recursion, and still be inspected: :data:`mcp_kymograph.events.MAX_READ_DEPTH`. Deeper, or too
#: deep for ``json.loads``, it is not inspected and counts as bounded, at the same depth on
#: every Python version. Above :data:`MAX_SCHEMA_DEPTH`, so that a deep schema in an otherwise
#: ordinary listing is still walked to its depth and the rest of the listing looked at.
MAX_INSPECTED_DEPTH = events.MAX_READ_DEPTH

#: Recorded field paths carry key names chosen by the server, so they are capped like the
#: recorder's redaction paths.
MAX_PATH_LENGTH = 200

#: ``serverInfo.name`` and ``.version`` are the server's own words and go into every finding
#: key, so they are capped like a method name.
MAX_SERVER_FIELD_LENGTH = 128

#: A locator carries names the server chose and is part of a key, so it is capped — but not
#: by cutting alone: two long locators that differ only past the cut would become one key.
#: A clipped locator ends in a digest of the whole one, which keeps it stable and distinct.
MAX_LOCATOR_LENGTH = 200
LOCATOR_DIGEST_LENGTH = 12


class Surface(str, Enum):
    """Where in a server message the text sat. Not a judgement, a location."""

    TOOL_DESCRIPTION = "tool_description"
    TOOL_TITLE = "tool_title"
    SCHEMA_FIELD_DESCRIPTION = "schema_field_description"
    SCHEMA_ENUM_VALUE = "schema_enum_value"
    TOOL_RESULT_TEXT = "tool_result_text"
    ERROR_MESSAGE = "error_message"
    RESOURCE_TEXT = "resource_text"
    #: The ``serverInfo`` of an ``initialize`` answer. Not walked: only the inspector sets it.
    SERVER_INFO = "server_info"


#: Surfaces that are the server documenting itself: short, written to be read by whoever
#: wires the tool up, and with no legitimate reason to carry markup, chat framing or padding.
#: The rest carried content from somewhere else, where all three are ordinary.
METADATA_SURFACES = frozenset(
    {
        Surface.TOOL_DESCRIPTION,
        Surface.TOOL_TITLE,
        Surface.SCHEMA_FIELD_DESCRIPTION,
        Surface.SCHEMA_ENUM_VALUE,
    }
)


class Reason(str, Enum):
    """Why a statement that applied to a message checked less than its path names."""

    #: The path resolved to nothing in this message.
    PATH_NOT_FOUND = "path_not_found"
    #: It resolved, but to no string — an object, a number, a list.
    NOT_A_STRING = "not_a_string"
    #: A work bound was reached before the statement had checked every place.
    BOUNDED = "bounded"


@dataclass(frozen=True, slots=True)
class Observation:
    """One place, one signal, seen by the built-in walk. Deduplicated per message on the pair."""

    surface: Surface
    path: str
    signal: Signal
    #: True when only the normalised text carried the signal, not the raw one.
    normalized: bool = False


@dataclass(frozen=True, slots=True)
class FindingKey:
    """What a finding is, as a store and a comparison between runs will match it — and all of it.

    **A position is never part of it.** ``result.tools[3].description`` moves to ``[4]`` the
    moment the server puts a tool in front; a key holding it would read that as one finding
    gone and another new. The key holds the ``locator`` instead — the same place by name,
    ``result.tools[name="search"].description`` (:mod:`mcp_kymograph.paths`). Renaming the tool
    changes the key, and should: a rename is a change. Inserting one does not.

    ``server`` is the **corpus entry's name**, given by the operator, and None
    for a run outside a corpus. It is never the name the server announces in ``initialize``:
    that name is chosen by the server under test, and a hostile server announcing a
    legitimate one's name must not be able to make its findings collide with that one's. The
    announced name is recorded beside the findings, and a difference is an event of its own.
    ``server_version`` is *not* its announced version either: it is the server's content
    identity, a digest over its own files or a pinned revision, established before the run
    (:mod:`mcp_kymograph.identity`), and None when the operator gave neither. ``tool_version`` is
    this tool's version. Kept apart, the two versions let a comparison tell a change in the
    server from a change in this tool.
    ``scenario`` and ``statement`` are names from the operator's file, ``signal`` a library ID.

    Two findings in one run share a key only when two elements share a name; a store counts
    them under it rather than telling them apart, because by identity they are one.
    """

    server: str | None
    server_version: str | None
    tool_version: str
    scenario: str | None
    statement: str
    locator: str
    signal: Signal

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "server_version": self.server_version,
            "tool_version": self.tool_version,
            "scenario": self.scenario,
            "statement": self.statement,
            "locator": self.locator,
            "signal": self.signal.value,
        }


@dataclass(frozen=True, slots=True)
class Finding:
    """One place where a statement's signal fired. The key says what; ``path`` says where in
    this message it sat, and is only ever that."""

    key: FindingKey
    path: str
    normalized: bool = False


@dataclass(frozen=True, slots=True)
class Evaluation:
    """What one statement did with one message: checked how much, and what fired.

    ``fired`` lists every signal the statement names, in its order, zero included — "asked
    and nothing fired" is a line, not an absence. ``reason`` is set when the statement checked
    less than its path names: nothing there, nothing that is a string, or a bound reached.
    """

    statement: str
    checked: int
    not_strings: int
    fired: tuple[tuple[Signal, int], ...]
    reason: Reason | None = None


@dataclass(frozen=True, slots=True)
class Look:
    """What the inspector made of one message.

    ``responded_method`` is returned even when nothing was observed: it is the correlation a
    message event otherwise cannot carry, and it is what lets a redaction in a *response* be
    located by method rather than only by direction and path.
    """

    responded_method: str | None = None
    message_id: str | int | None = None
    #: The method entries in this message are filed under: the one it answers, or for a
    #: server request or notification its own. Kept apart from ``responded_method``, which
    #: is a correlation and must stay None for a message that answers nothing.
    method: str | None = None
    observations: tuple[Observation, ...] = ()
    #: The true number before :data:`MAX_OBSERVATIONS_PER_MESSAGE` was applied.
    total: int = 0
    findings: tuple[Finding, ...] = ()
    #: Findings made past :data:`MAX_FINDINGS_PER_MESSAGE`: ``(statement, signal, how many)``,
    #: in the order they were made. Empty when nothing was cut.
    findings_cut: tuple[tuple[str, str, int], ...] = ()
    evaluations: tuple[Evaluation, ...] = ()
    #: Whether a work bound stopped the walk before the message was exhausted.
    bounded: bool = False
    #: Whether the message was not valid UTF-8 and was inspected as a client reads it, with
    #: replacement characters. Always bounded too: what the replacement hides is not seen.
    undecodable: bool = False
    #: Whether this message was the answer to ``initialize`` (or, in the modern era, to
    #: ``server/discover``); then ``announced`` is the name the server gave for itself there
    #: (capped, None if it gave none as a string).
    answered_initialize: bool = False
    announced: str | None = None


#: What a message that was not inspected looks like: nothing correlated, nothing seen.
#: One shared instance rather than a fresh empty Look per frame — it is immutable.
NOTHING_SEEN = Look()


def signals_in(text: str, surface: Surface) -> Iterator[Signal]:
    """Which of the walk's signals this string carries on this surface, in library order."""
    subject = Subject(text)
    walk = WALK_METADATA if surface in METADATA_SURFACES else WALK_CONTENT
    return (signal for signal in walk if check(signal, subject) is not None)


# -- the surfaces -------------------------------------------------------------------------


def _unchanged(text: str) -> str:
    return text


def surfaces(
    document: Any,
    responded_method: str | None,
    budget: _Budget | None = None,
    scrub: Callable[[str], str] = _unchanged,
) -> Iterator[tuple[Surface, str, str]]:
    """Every ``(surface, path, text)`` this message exposes, given the method it answers.

    An error response is inspected whatever it answers — including a request we never saw,
    where ``responded_method`` is None — because ``error.message`` is a surface of its own.
    A ``result`` object is read even beside an ``error`` key: the SDKs parse such a message as
    a result.
    A schema nested past :data:`MAX_SCHEMA_DEPTH` spends ``budget``, if one is given.
    ``scrub`` is applied to each key of ``structuredContent`` and of a tool's schemas before
    the key is cut, see :func:`_string_surfaces`.

    A ``tools/call`` answer exposes three places a client can hand to a model: the ``text`` of
    a ``content`` entry, the ``text`` of a resource embedded in one
    (``content[i].resource.text``, whatever the entry's ``type`` says) and every string in
    ``structuredContent``, in that order. The last is walked like a schema, to the same depth.
    """
    if not isinstance(document, dict):
        return
    error = document.get("error")
    if isinstance(error, dict) and isinstance(error.get("message"), str):
        yield Surface.ERROR_MESSAGE, "error.message", error["message"]

    result = document.get("result")
    if not isinstance(result, dict):
        return

    if responded_method == "tools/list":
        yield from _tool_surfaces(result, budget, scrub)
    elif responded_method == "tools/call":
        yield from _content_surfaces(result.get("content"))
        if "structuredContent" in result:
            yield from _string_surfaces(
                result["structuredContent"], "result.structuredContent", budget, 0, scrub
            )
    elif responded_method == "resources/read":
        yield from _text_items(result.get("contents"), "result.contents", Surface.RESOURCE_TEXT)


def _tool_surfaces(
    result: dict, budget: _Budget | None, scrub: Callable[[str], str]
) -> Iterator[tuple[Surface, str, str]]:
    tools = result.get("tools")
    if not isinstance(tools, list):
        return
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            continue
        base = f"result.tools[{index}]"
        if isinstance(tool.get("description"), str):
            yield Surface.TOOL_DESCRIPTION, f"{base}.description", tool["description"]
        if isinstance(tool.get("title"), str):
            yield Surface.TOOL_TITLE, f"{base}.title", tool["title"]
        annotations = tool.get("annotations")
        if isinstance(annotations, dict) and isinstance(annotations.get("title"), str):
            yield Surface.TOOL_TITLE, f"{base}.annotations.title", annotations["title"]
        for key in ("inputSchema", "outputSchema"):
            schema = tool.get(key)
            if isinstance(schema, (dict, list)):
                yield from _schema_surfaces(schema, f"{base}.{key}", budget, 0, scrub)


def _schema_surfaces(
    node: Any, path: str, budget: _Budget | None, depth: int, scrub: Callable[[str], str]
) -> Iterator[tuple[Surface, str, str]]:
    """Every ``description`` and every string ``enum`` member anywhere under a schema, down to
    :data:`MAX_SCHEMA_DEPTH`.

    Walked generically rather than by a fixed shape: JSON Schema nests without limit
    (``properties``, ``items``, ``$defs``, ``anyOf``), and a description four levels down
    reaches a model exactly as the top one does.

    A key is recognised as it came, and only the path carries it scrubbed, once, whole, then
    clipped, as in :func:`_string_surfaces`: a key of n characters over m enum members costs
    n + m paths of bounded length, not n * m.
    """
    if not isinstance(node, (dict, list)):
        return  # a scalar is no level of its own: ``"type": "string"`` beside a description
    if depth > MAX_SCHEMA_DEPTH:
        if budget is not None:
            budget.spent = True
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child = _clip(f"{path}.{_clip(scrub(key))}")
            if key == "description" and isinstance(value, str):
                yield Surface.SCHEMA_FIELD_DESCRIPTION, child, value
            elif key == "enum" and isinstance(value, list):
                for index, member in enumerate(value):
                    if isinstance(member, str):
                        yield Surface.SCHEMA_ENUM_VALUE, _clip(f"{child}[{index}]"), member
            else:
                yield from _schema_surfaces(value, child, budget, depth + 1, scrub)
    else:
        for index, item in enumerate(node):
            yield from _schema_surfaces(item, _clip(f"{path}[{index}]"), budget, depth + 1, scrub)


def _content_surfaces(items: Any) -> Iterator[tuple[Surface, str, str]]:
    """The ``text`` of each entry, then the ``text`` of the resource embedded in it."""
    if not isinstance(items, list):
        return
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        base = f"result.content[{index}]"
        if isinstance(item.get("text"), str):
            yield Surface.TOOL_RESULT_TEXT, f"{base}.text", item["text"]
        resource = item.get("resource")
        if isinstance(resource, dict) and isinstance(resource.get("text"), str):
            yield Surface.RESOURCE_TEXT, f"{base}.resource.text", resource["text"]


def _string_surfaces(
    node: Any, path: str, budget: _Budget | None, depth: int, scrub: Callable[[str], str]
) -> Iterator[tuple[Surface, str, str]]:
    """Every string under ``node``, values only, down to :data:`MAX_SCHEMA_DEPTH`.

    Each key is scrubbed once, whole, then clipped, and only then hung on the path, which is
    clipped at every level: the scrubber needs all of a key to know a literal in it, so a cut
    before it would leave the head of one behind, and a path kept whole would be copied and
    scrubbed again for every string under a long key. Done this way, the work per message is
    the sum of its key lengths plus a path's bound for each string, and a path has the form it
    had before keys were scrubbed here. A long key above a wide list is still the case to
    keep in mind: the key is handled once, but every member costs a path.
    """
    if isinstance(node, str):
        yield Surface.TOOL_RESULT_TEXT, path, node
        return
    if not isinstance(node, (dict, list)):
        return
    if depth > MAX_SCHEMA_DEPTH:
        if budget is not None:
            budget.spent = True
        return
    if isinstance(node, dict):
        for key, value in node.items():
            child = _clip(f"{path}.{_clip(scrub(key))}")
            yield from _string_surfaces(value, child, budget, depth + 1, scrub)
    else:
        for index, item in enumerate(node):
            child = _clip(f"{path}[{index}]")
            yield from _string_surfaces(item, child, budget, depth + 1, scrub)


def _text_items(items: Any, path: str, surface: Surface) -> Iterator[tuple[Surface, str, str]]:
    if not isinstance(items, list):
        return
    for index, item in enumerate(items):
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            yield surface, f"{path}[{index}].text", item["text"]


# -- the inspector ------------------------------------------------------------------------


class _Budget:
    """The work bounds for one message, shared by the walk and every statement.

    One budget for both, so a statement over ``result.tools[*]`` on a hostile listing costs
    exactly what the walk's own visit would. Once spent it stays spent.
    """

    __slots__ = ("strings", "characters", "spent")

    def __init__(self) -> None:
        self.strings = 0
        self.characters = 0
        self.spent = False

    def take(self, text: str) -> bool:
        if self.spent:
            return False
        self.strings += 1
        self.characters += len(text)
        if self.strings > MAX_SCANNED_STRINGS or self.characters > MAX_SCANNED_CHARS:
            self.spent = True
        return not self.spent


class Inspector:
    """Reads one session's server traffic. Holds the id-to-method table and the tallies.

    Nothing here blocks, raises upwards or touches the forwarding path. It is called from
    the observer, on a copy, and a message it cannot parse is simply not inspected.
    """

    __slots__ = (
        "_method_by_id",
        "_server_method_by_id",
        "_by_method",
        "_bounded",
        "_client_undecodable",
        "_statements",
        "_by_statement",
        "_scenario",
        "_server",
        "_server_version",
        "_announced",
        "_replaced",
        "_scrub",
    )

    def __init__(
        self,
        statements: Sequence[Any] = (),
        scenario: str | None = None,
        server_version: str | None = None,
        server: str | None = None,
        scrub: Callable[[str], str] | None = None,
    ) -> None:
        #: What the run keeps secret, applied to every text of the server that this class hands
        #: on: the announced name, the paths and the locators of a key. They are the server's
        #: words, and a server may send back what it was sent. The recorder's own masking of
        #: payloads cannot reach them, because they are made here, from the parsed document.
        self._scrub = scrub if scrub is not None else str
        #: Requests the client sent, answered by the server — the ones whose answers are
        #: inspected. Keyed by :func:`mcp_kymograph.correlation.key_of`.
        self._method_by_id: dict[correlation.Key, str] = {}
        #: Requests the server sent (sampling, elicitation), answered by the client. Kept apart
        #: so that one of them can never take the place of a client request with the same id.
        self._server_method_by_id: dict[correlation.Key, str] = {}
        self._by_method: dict[str, int] = {}
        self._bounded = 0
        self._client_undecodable = 0
        #: Scenario statements (:class:`mcp_kymograph.scenario.Statement`), in file order.
        self._statements = tuple(statements)
        # Every statement starts at zero for every signal it names, so a run summary can say
        # "asked, and never seen" rather than leave out what did not fire.
        self._by_statement: dict[str, dict[Signal, int]] = {
            s.name: dict.fromkeys(s.signals, 0) for s in self._statements
        }
        self._scenario = scenario
        self._server = server
        self._server_version = server_version
        self._announced: str | None = None
        #: Whether the name :meth:`_remember_server` kept last had a lone surrogate replaced.
        self._replaced = False

    @property
    def observations_by_method(self) -> dict[str, int]:
        """How many observations the walk made, per method, counted before the per-message cap.

        Keyed by the method the message answers; ``"unknown"`` for a response whose request
        was never seen. Counted where the inspection happens rather than where the event is
        written, so a summary stays true even when an observation event was dropped from a
        full queue — the same rule the engine's hit count follows.
        """
        return dict(self._by_method)

    @property
    def findings_by_statement(self) -> dict[str, dict[str, int]]:
        """How many findings each statement made, per signal it names, zeros included."""
        return {
            name: {signal.value: count for signal, count in counts.items()}
            for name, counts in self._by_statement.items()
        }

    @property
    def announced_server(self) -> str | None:
        """The name the server gave for itself in its ``initialize`` answer, capped. Recorded,
        never keyed on."""
        return self._announced

    @property
    def bounded_messages(self) -> int:
        """How many messages a work bound stopped the walk on, leaving them under-inspected.

        Reported rather than swallowed: without it, a run that went quiet because the
        inspector ran out of budget would read exactly like a run that found nothing. An answer
        from the server whose id the clients would not agree on is counted here too: no method
        can be tied to it, so its surfaces were not looked at, and a client may take it all the
        same.
        """
        return self._bounded

    @property
    def client_undecodable(self) -> int:
        """How many whole client-to-server messages were not valid UTF-8, JSON or not.

        Kept apart from :attr:`bounded_messages`: what the client sends is the client's doing
        and is not counted against the server. The verdict marks the run as bounded with a
        cause of its own.
        """
        return self._client_undecodable

    def count_bounded(self) -> None:
        """Count one message as not seen in full, for a reason only the caller knows: the
        engine could not read it. The caller sees to it that a message is counted once."""
        self._bounded += 1

    def learn(
        self, document: Any, direction: Direction | None = Direction.CLIENT_TO_SERVER
    ) -> None:
        """Remember which id asked which method, in the table of the direction it was sent in.

        A request from the server goes to its own table; anything else, ``None`` included, is
        taken as the client's.
        """
        if not isinstance(document, dict):
            return
        method = document.get("method")
        key = correlation.key_of(document.get("id"))
        if isinstance(method, str) and key is not None and key is not correlation.AMBIGUOUS:
            table = (
                self._server_method_by_id
                if direction is Direction.SERVER_TO_CLIENT
                else self._method_by_id
            )
            if len(table) >= MAX_TRACKED_IDS:
                table.clear()
            table[key] = method

    def look(self, direction: Direction | None, raw: bytes) -> Look:
        """Inspect one framed message, in whichever direction it went.

        Client-to-server messages are only learned from, never inspected: what the client
        sends is not the server delivering content to an agent. Server-to-client messages
        are both, because a server sends requests of its own (sampling, elicitation) whose
        ids the correlation table needs as much.
        """
        document, too_deep, repeated, undecodable = _parse(raw)
        if undecodable and direction is Direction.CLIENT_TO_SERVER:
            self._client_undecodable += 1
        if document is None and not too_deep:
            return Look()
        self.learn(document, direction)  # from the top level, however deep the rest is
        if direction is not Direction.SERVER_TO_CLIENT:
            return Look()
        if too_deep:
            # Not inspected at all: from the server, that is a message the observer did not
            # look at in full, and it is counted so.
            self._bounded += 1
            return Look(bounded=True, undecodable=undecodable)

        responded = self._responded_method(document)
        # The opening's answer announces the server's name: ``initialize``'s in legacy, and in
        # the modern era the probe's. An error answer to the probe announces nothing: a legacy
        # server's -32601 or a modern server's -32022 names no one, and the name then comes from
        # ``initialize`` (or the run stopped before one).
        answered_initialize = responded == "initialize" or (
            responded == PROBE_METHOD and isinstance(document.get("result"), dict)
        )
        self._replaced = False
        if answered_initialize:
            self._remember_server(document, responded)
        method = responded if responded is not None else _own_method(document)
        budget = _Budget()
        observations, total, cut = self._walk(document, responded, budget)
        findings, findings_cut, evaluations, statements_cut = self._evaluate(
            document, responded, budget
        )
        if self._replaced:
            # The inspector's own statement, not the walk's: the name was kept with U+FFFD in
            # place of a surrogate. Counted and capped like every observation.
            total += 1
            if len(observations) < MAX_OBSERVATIONS_PER_MESSAGE:
                observations += (
                    Observation(
                        Surface.SERVER_INFO, "result.serverInfo.name", Signal.LONE_SURROGATE, False
                    ),
                )
        if total:
            key = method or "unknown"
            self._by_method[key] = self._by_method.get(key, 0) + total
        # An answer no method can be tied to because the clients would not agree on its id: none
        # of its surfaces was looked at, and some client may take it as the answer it waits for.
        unmatched = _is_answer(document) and (
            correlation.key_of(document.get("id")) is correlation.AMBIGUOUS
        )
        # Read as the clients read it, the last value; but another reader may take the first,
        # and the recorder does not keep such a message as a document: not seen in full.
        # A message that was not valid UTF-8 is read here as a client reads it, but what the
        # replacement characters stand for was not seen: not seen in full either.
        bounded = budget.spent or cut or statements_cut or unmatched or repeated or undecodable
        if bounded:
            self._bounded += 1
        return Look(
            responded_method=responded,
            message_id=_id_of(document),
            method=method,
            observations=observations,
            total=total,
            findings=findings,
            findings_cut=findings_cut,
            evaluations=evaluations,
            bounded=bounded,
            undecodable=undecodable,
            answered_initialize=answered_initialize,
            announced=self._announced if answered_initialize else None,
        )

    def _walk(
        self, document: Any, responded: str | None, budget: _Budget
    ) -> tuple[tuple[Observation, ...], int, bool]:
        """The built-in walk: every known surface, the walk's signals for that surface."""
        kept: list[Observation] = []
        total = 0
        cut = False
        seen: set[tuple[str, Signal]] = set()
        for surface, path, text in surfaces(document, responded, budget, self._scrub):
            if not budget.take(text):
                break
            clipped = _clip(self._scrub(path))
            subject = Subject(text)
            walk = WALK_METADATA if surface in METADATA_SURFACES else WALK_CONTENT
            for signal in walk:
                via = check(signal, subject)
                if via is None or (clipped, signal) in seen:
                    continue
                seen.add((clipped, signal))
                total += 1
                if len(kept) < MAX_OBSERVATIONS_PER_MESSAGE:
                    kept.append(Observation(surface, clipped, signal, via is Via.NORMALIZED))
            cut = cut or subject.cut
        return tuple(kept), total, cut

    def _evaluate(
        self, document: Any, responded: str | None, budget: _Budget
    ) -> tuple[tuple[Finding, ...], tuple[tuple[str, str, int], ...], tuple[Evaluation, ...], bool]:
        """Every statement that applies to this message, in file order, each with a record."""
        kept: list[Finding] = []
        over: dict[tuple[str, str], int] = {}
        evaluations: list[Evaluation] = []
        cut = False
        names: list[NameIndex] = []

        def listing() -> NameIndex:
            # Built at most once per message, and only if a statement asks for a collision.
            if not names:
                names.append(NameIndex.of(document))
            return names[0]

        for statement in self._statements:
            if not statement.applies_to(document, responded):
                continue
            counts = dict.fromkeys(statement.signals, 0)
            checked = 0
            not_strings = 0
            reason: Reason | None = None
            seen: set[tuple[str, Signal]] = set()
            locations = resolve(document, statement.path)
            for location in locations:
                if not isinstance(location.value, str):
                    not_strings += 1
                    continue
                if not budget.take(location.value):
                    reason = Reason.BOUNDED
                    break
                checked += 1
                clipped = _clip(self._scrub(location.path))
                subject = Subject(location.value, listing)
                for signal in statement.signals:
                    via = check(signal, subject)
                    if via is None or (clipped, signal) in seen:
                        continue
                    seen.add((clipped, signal))
                    counts[signal] += 1
                    self._by_statement[statement.name][signal] += 1
                    if len(kept) < MAX_FINDINGS_PER_MESSAGE:
                        key = self._key(statement.name, location.locator, signal)
                        kept.append(Finding(key, clipped, via is Via.NORMALIZED))
                    else:
                        tally = (statement.name, signal.value)
                        over[tally] = over.get(tally, 0) + 1
                cut = cut or subject.cut
            if reason is None and not locations:
                reason = Reason.PATH_NOT_FOUND
            elif reason is None and not checked:
                reason = Reason.NOT_A_STRING
            evaluations.append(
                Evaluation(statement.name, checked, not_strings, tuple(counts.items()), reason)
            )
        cut_findings = tuple((s, g, n) for (s, g), n in over.items())
        return tuple(kept), cut_findings, tuple(evaluations), cut

    def _key(self, statement: str, locator: str, signal: Signal) -> FindingKey:
        return FindingKey(
            server=self._server,
            server_version=self._server_version,
            tool_version=__version__,
            scenario=self._scenario,
            statement=statement,
            locator=_clip_locator(self._scrub(locator)),
            signal=signal,
        )

    def _remember_server(self, document: Any, method: str = "initialize") -> None:
        """Note the name an ``initialize`` answer announces — to record it, not to key on it.
        The modern era announces it in the answer to ``server/discover``, in
        ``result._meta["io.modelcontextprotocol/serverInfo"]``: as self-reported as the legacy
        one.

        Neither the announced name nor the announced version goes into a key: both are
        chosen by the server under test.
        """
        result = document.get("result") if isinstance(document, dict) else None
        if method == PROBE_METHOD:
            meta = result.get("_meta") if isinstance(result, dict) else None
            info = meta.get(META_SERVER_INFO) if isinstance(meta, dict) else None
        else:
            info = result.get("serverInfo") if isinstance(result, dict) else None
        name = info.get("name") if isinstance(info, dict) else None
        self._announced = server_field(self._scrub(name) if isinstance(name, str) else name)
        self._replaced = replaced_surrogate(name)

    def _responded_method(self, document: Any) -> str | None:
        """The method of the client request a server message answers, or None. Only the
        client's table: a request the server sent is answered by the client, never by itself."""
        if not _is_answer(document):
            return None
        key = correlation.key_of(document.get("id"))
        if key is None or key is correlation.AMBIGUOUS:
            return None
        return self._method_by_id.get(key)


def _clip_locator(locator: str) -> str:
    if len(locator) <= MAX_LOCATOR_LENGTH:
        return locator
    digest = hashlib.sha256(locator.encode("utf-8", "surrogatepass")).hexdigest()
    keep = MAX_LOCATOR_LENGTH - LOCATOR_DIGEST_LENGTH - 2
    return f"{locator[:keep]}…#{digest[:LOCATOR_DIGEST_LENGTH]}"


_LONE_SURROGATES = dict.fromkeys(range(0xD800, 0xE000), "\N{REPLACEMENT CHARACTER}")


def replaced_surrogate(value: Any) -> bool:
    """Whether :func:`server_field` puts U+FFFD in place of a lone surrogate in this value."""
    return isinstance(value, str) and value != value.translate(_LONE_SURROGATES)


def server_field(value: Any) -> str | None:
    """A ``serverInfo`` member as it goes into a key: a string, capped, or None.

    A lone surrogate (a JSON ``\\ud800`` escape) is no text, and neither the recording nor
    the store's database can encode it: it becomes U+FFFD before the name is kept.
    """
    if not isinstance(value, str):
        return None
    value = value.translate(_LONE_SURROGATES)
    if len(value) <= MAX_SERVER_FIELD_LENGTH:
        return value
    return value[:MAX_SERVER_FIELD_LENGTH] + "…"


def _own_method(document: Any) -> str | None:
    method = document.get("method") if isinstance(document, dict) else None
    return method if isinstance(method, str) else None


def _parse(raw: bytes) -> tuple[Any | None, bool, bool, bool]:
    """The document, whether it nests deeper than :data:`MAX_INSPECTED_DEPTH` — then only
    its top level, for its id and method — whether any object in it repeats a key, and
    whether the message was not valid UTF-8. None for a message that is not a document.

    A message that is not valid UTF-8 is parsed from its text with replacement characters,
    as a client reads it, by the same depth and repeat rules.

    A repeated key reads as the clients read it: the last value wins, as in ``json.loads``.
    The parser's own hook notes the repeat, in one pass; nothing walks the document again.
    The depth rules are those of :func:`events.load`, which cannot take a hook.
    """
    text, valid = events.decode(raw)
    undecodable = not valid
    limit = MAX_INSPECTED_DEPTH
    if text.count("[") + text.count("{") > limit:
        depth = events.nesting(text)
        if depth is None:
            return None, False, False, undecodable
        if depth > limit:
            return events.top_level(text), True, False, undecodable
    repeated = False

    def last_wins(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal repeated
        members = dict(pairs)
        if len(members) != len(pairs):
            repeated = True
        return members

    try:
        return json.loads(text, object_pairs_hook=last_wins), False, repeated, undecodable
    except ValueError:
        return None, False, False, undecodable
    except RecursionError:  # within the limit, from a stack already nearly spent
        return events.top_level(text), True, False, undecodable


def _is_answer(document: Any) -> bool:
    """Whether a message can be an answer: an object without a ``method`` member."""
    return isinstance(document, dict) and "method" not in document


def _id_of(document: Any) -> str | int | None:
    return correlation.message_id(document.get("id")) if isinstance(document, dict) else None


def _clip(path: str) -> str:
    return path if len(path) <= MAX_PATH_LENGTH else path[:MAX_PATH_LENGTH] + "…"
