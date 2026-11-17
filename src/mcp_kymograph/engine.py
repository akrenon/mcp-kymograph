"""The decision point: what happens to each message on its way through.

This sits in the *forwarding* path, not the observer path. It changes what reaches the other
side, so it is synchronous and cannot block — a rule that needed to wait would be a design
error, not a reason for ``await``. Deciding is pure CPU on one already-framed message.

Default is always pass. With no rules — an empty or absent scenario — :meth:`Engine.decide`
returns ``PASS`` after doing nothing, and the tool only forwards and observes. ``active``
is how the proxy knows whether to frame the forwarding path at all: only an active engine
turns a direction from chunk-forwarding into message-forwarding.

The engine works on the *real* traffic, never the masked recording. Masking happens later,
when the intervention event is written; a rule that saw the masked form could not recognise
what it is meant to act on (a tool description containing "token" would already be redacted).

Rules are matched to responses by request id, not by order: the proxy showed that requests
run concurrently. The engine watches requests in both directions to learn which id asked
which method, so that a response — which carries only an id — can be tied back to its method.
It keeps one table per direction, and a response is looked up in the table of the direction
opposite to its own: a server request cannot take the place of a client request with the same
id. Ids are compared as the clients compare them (:mod:`mcp_kymograph.correlation`).

**Every rule that matches a message acts on it, in scenario order.** The rules form a chain:
each sees the document as the rules before it left it, and each that took part leaves a
:class:`Step` — including one that matched and changed nothing, which says so and why. The
older convention, first change wins, had a silent dead path: a second matching rule had no
effect and left no trace, which is the wrong failure for a tool whose output is evidence.
Scenario order is the only ordering key. ``drop`` ends the chain, because nothing after it
would reach anyone. The document is serialised **once**, after the last step — whatever a
transport needs around the message (the stdio newline today, a length header later) is
computed from those final bytes, never carried over from the original.

A rule that fails mid-chain takes the whole chain with it for that message: the untouched
original goes out, and none of the earlier steps counts as a hit. Half a chain is a message
no scenario describes.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar, Protocol

from mcp_kymograph import correlation, events
from mcp_kymograph.events import Direction

#: A request id maps to at most this many remembered methods before the oldest are forgotten.
#: A server that never answers cannot make the id table grow without bound.
MAX_TRACKED_IDS = 4096


class Action(str, Enum):
    FORWARD = "forward"
    REPLACE = "replace"
    DROP = "drop"


class RuleErrorPolicy(str, Enum):
    """What a failing rule costs: the run, or only itself.

    ``ABORT`` is the default and the older behaviour: forward the untouched original, then
    end the run cleanly. Nothing invalid goes out and the connection is never damaged, but
    a rule that misfires late in a long assessment takes the whole run with it.

    ``CONTINUE`` stills only the rule that failed. Its hits — the ones already recorded and
    any it would have made later — are marked invalid in the report, the untouched original
    is forwarded, and the remaining rules carry on. Interception as a whole stays on: this
    quarantines one rule, it does not switch the engine off.
    """

    ABORT = "abort"
    CONTINUE = "continue"


class RuleFailure(Exception):
    """A rule failed. Carries *which* rule, so a policy can act on that rule alone.

    Without the name there is no way to still one rule and keep the rest: the proxy would
    only know that something in the engine went wrong. Every failure that a policy may be
    applied to therefore names its rule.
    """

    #: The ``reason`` a run or a quarantine is recorded under.
    reason: ClassVar[str] = "rule_error"

    def __init__(self, rule: str, detail: str) -> None:
        super().__init__(f"{rule} {detail}")
        self.rule = rule
        self.detail = detail
        #: The id of the message being decided when the rule failed. Filled in by
        #: :meth:`Engine.decide`, which is the only place that knows it.
        self.message_id: str | int | None = None


class InvalidReplacement(RuleFailure):
    """A rule produced bytes that are not valid JSON. It must not go out silently."""

    reason: ClassVar[str] = "invalid_replacement"


class RuleError(RuleFailure):
    """A rule raised on its way through ``act``. The bug is the rule's, not the traffic's."""

    reason: ClassVar[str] = "rule_error"


@dataclass(frozen=True, slots=True)
class Change:
    """One value a rule changed: where, what it was, what it became.

    ``path`` is the concrete spelling, the same form a recording uses. ``""`` is the whole
    document — what a rule written in code changes when it hands back a new one.
    """

    path: str
    before: Any
    after: Any


@dataclass(frozen=True, slots=True)
class Edited:
    """What a rule returns after changing the working document in place.

    ``action`` is the rule's own word for what it did (``replace``, ``inject``), so the record
    keeps the difference between overwriting a value and adding to it. ``skipped`` names places
    the path reached but the action could not apply to, with our reason — a partial effect is
    still not a silent one.
    """

    action: str
    changes: tuple[Change, ...]
    skipped: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class NoEffect:
    """What a rule returns when the message is one it is meant for and it changed nothing.

    Distinct from returning None, which means "not my message". A rule for ``tools/list``
    whose path is not in this ``tools/list`` has taken part and come up empty, and the
    record has to say so — otherwise a scenario that never landed reads like one that was
    never meant to.
    """

    action: str
    reason: str
    skipped: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class Step:
    """One rule's part in deciding one message. ``reason`` is set exactly when it had none."""

    rule: str
    action: str
    changes: tuple[Change, ...] = ()
    reason: str | None = None
    skipped: tuple[tuple[str, str], ...] = ()

    @property
    def effective(self) -> bool:
        return self.reason is None


#: How a rule written in code that returns a whole new document is recorded.
REPLACE_DOCUMENT = "replace_document"


@dataclass(frozen=True, slots=True)
class Outcome:
    """What the engine decided for one message.

    ``replacement`` is the exact bytes to forward for a REPLACE; the parsed documents are
    carried alongside so the intervention event can mask and record both without re-parsing.
    ``steps`` is every rule that took part, in the order it did — non-empty also for a
    FORWARD when rules matched and changed nothing, because that is worth a record too.
    """

    action: Action
    message_id: str | int | None = None
    replacement: bytes | None = None
    original_document: Any = None
    replacement_document: Any = None
    steps: tuple[Step, ...] = ()
    #: The message was not valid UTF-8 and went on unchanged while a rule is active for its
    #: direction: no rule could read it as a client does. Not a rule's doing, so no step.
    unreadable: bool = False

    @classmethod
    def passthrough(cls) -> Outcome:
        return cls(action=Action.FORWARD)


class Rule(Protocol):
    """One transformation. Pure: it inspects a parsed document and returns what to do.

    ``responded_method`` is the method of the request this message answers, or None when the
    message is not a response or its request was never seen. It is how a rule keys on
    ``tools/list`` without trusting message order.
    """

    name: str

    #: The directions this rule may modify. A rule that leaves this off is assumed to modify
    #: any direction — safe, but it forfeits the optimisation of leaving an untouched
    #: direction on the fast chunk path. Declaring it narrowly is how a rule keeps the
    #: direction it never touches free of message-wise buffering. Leaving it off is warned
    #: about once, when the rule is loaded (see :meth:`Engine.undeclared_directions`), so
    #: the most expensive setting is never reached silently.
    directions: frozenset[Direction]

    def act(
        self, direction: Direction, document: Any, responded_method: str | None
    ) -> dict | Action | Edited | NoEffect | None:
        """Decide this rule's part in one message.

        None: not this rule's message. :attr:`Action.DROP`: drop it. :class:`Edited`: the rule
        changed ``document`` in place. :class:`NoEffect`: the rule's message, nothing changed.
        A dict: a whole new document; ``document`` itself must then be left as it was.
        """
        ...


class Engine:
    """Runs the rules for one session. Stateful only in the id-to-method tables."""

    def __init__(self, rules: Sequence[Rule] = ()) -> None:
        self._rules = tuple(rules)
        #: Requests the client sent, keyed by :func:`mcp_kymograph.correlation.key_of`; the
        #: server's answers are looked up here.
        self._method_by_id: dict[correlation.Key, str] = {}
        #: Requests the server sent; the client's answers are looked up here.
        self._server_method_by_id: dict[correlation.Key, str] = {}
        self._quarantined: set[str] = set()
        self._quarantined_order: list[str] = []
        self._hits: dict[str, int] = {}

    @property
    def active(self) -> bool:
        """Whether any rule exists. An inactive engine leaves the forwarding path untouched."""
        return bool(self._rules)

    @property
    def quarantined(self) -> tuple[str, ...]:
        """Rules that failed and were stilled, in the order they were stilled."""
        return tuple(self._quarantined_order)

    def hits(self, rule_name: str) -> int:
        """How often this rule changed or dropped a message.

        Counted where the decision is made, not where the intervention event is written, so
        a recording that lost an event to a full queue still reports the true number of hits
        a quarantine invalidates.
        """
        return self._hits.get(rule_name, 0)

    def quarantine(self, rule_name: str) -> bool:
        """Still one rule for the rest of the run. Returns whether it was running until now.

        Only ``decide`` honours this. ``active`` and ``modifies`` keep describing the
        scenario as it was declared, because the forwarding path chooses chunk-wise or
        message-wise framing once, when a pump starts, and cannot be re-framed underneath a
        half-read message. A quarantine therefore costs the buffering it already paid for —
        it buys back correctness, not speed.
        """
        if rule_name in self._quarantined:
            return False
        self._quarantined.add(rule_name)
        self._quarantined_order.append(rule_name)
        return True

    def undeclared_directions(self) -> tuple[str, ...]:
        """Names of rules that did not say which directions they modify.

        Such a rule is assumed to modify every direction, which is safe but is also the most
        expensive setting there is: both directions leave the chunk path for message-wise
        buffering. The caller warns once per rule at load time — never per message, which
        would put a print in the forwarding path.
        """
        return tuple(rule.name for rule in self._rules if getattr(rule, "directions", None) is None)

    def modifies(self, direction: Direction) -> bool:
        """Whether any rule may change this direction — the test for message-wise forwarding.

        Only a direction a rule can modify pays the cost of being forwarded message by
        message. The other direction stays on the chunk path, and the engine still
        learns request ids from it through the observer copy (see ``observe``), so matching a
        response by id keeps working without buffering that direction.

        **This bounds buffering, not stalling.** A rule runs synchronously on the event loop,
        which both directions share, so the time a rule spends in ``act`` holds up everything,
        including the direction it never touches. Measured: a rule sleeping 2s per message
        stalled the loop for 2.04s. Rules must be fast; the
        watchdog in the proxy is the backstop for one that is not.
        """
        for rule in self._rules:
            declared = getattr(rule, "directions", None)
            if declared is None or direction in declared:
                return True
        return False

    def _acting_on(self, direction: Direction) -> bool:
        """Whether a rule that is not quarantined may change this direction: the rules that
        would have read a message here, had it been readable."""
        for rule in self._rules:
            if rule.name in self._quarantined:
                continue
            declared = getattr(rule, "directions", None)
            if declared is None or direction in declared:
                return True
        return False

    def observe(self, direction: Direction, raw: bytes) -> None:
        """Learn request ids from a direction that is only watched, not modified.

        Runs on the observer path, on a copy, never on the forwarding path — so it cannot
        hold up the connection. It only remembers which id asked which method; it never
        changes anything.
        """
        if not self._rules:
            return
        document, _, _ = self._read(raw)
        if document is not None:
            self._remember_request(direction, document)  # from the top level, however deep

    def decide(self, direction: Direction, raw: bytes) -> Outcome:
        """Decide what to do with one framed message. Never blocks, never awaits.

        Anything that is not parseable JSON passes through untouched: the engine cannot act
        on what it cannot read, and it must not turn a message it does not understand into a
        dropped or corrupted one.
        """
        if not self._rules:
            return Outcome.passthrough()

        document, too_deep, undecodable = self._read(raw)
        if document is not None:
            self._remember_request(direction, document)  # from the top level, however deep
        if document is not None and undecodable:
            # Its id is learned as a client reads the message, with replacement characters.
            # The bytes are not rewritten: no rule edits what it cannot read faithfully. The
            # outcome says so, for the observer to count it as not seen in full.
            return Outcome(action=Action.FORWARD, unreadable=self._acting_on(direction))
        if document is None or too_deep:
            # Deeper than a rule's copy of it could follow on every Python version: it passes
            # untouched, rather than the server's nesting stopping the engine or being blamed
            # on a rule. Its id is learned all the same, so that a flat answer to it is not
            # left without its method.
            return Outcome.passthrough()
        responded_method = self._responded_method(direction, document)
        message_id = _id_of(document)

        try:
            return self._run_chain(direction, raw, document, responded_method, message_id)
        except RuleFailure as failure:
            # Attached here because this is the only place that knows both. The caller needs
            # the id to record *which* message the rule broke on.
            failure.message_id = message_id
            raise

    def _run_chain(
        self,
        direction: Direction,
        raw: bytes,
        document: Any,
        responded_method: str | None,
        message_id: str | int | None,
    ) -> Outcome:
        # `document` was parsed from `raw` for this call alone, so the chain may change it in
        # place. The original is not copied up front — most messages match no rule — but
        # parsed again from the bytes, which are the original by definition, once a step
        # has actually changed something.
        current = document
        steps: list[Step] = []
        dropped = False
        for rule in self._rules:
            if rule.name in self._quarantined:
                continue
            try:
                result = rule.act(direction, current, responded_method)
            except Exception as exc:  # noqa: BLE001 - a rule may have a bug; it must be named
                # Named, not re-raised bare: the caller has to know which rule failed to be
                # able to still that one alone. Without the name the only available answer
                # would be to end the run, whatever the policy says.
                raise RuleError(rule.name, f"raised {type(exc).__name__}") from exc
            if result is None:
                continue
            if result is Action.DROP:
                steps.append(Step(rule=rule.name, action=Action.DROP.value))
                dropped = True
                break
            if isinstance(result, NoEffect):
                steps.append(
                    Step(rule.name, result.action, reason=result.reason, skipped=result.skipped)
                )
            elif isinstance(result, Edited):
                steps.append(
                    Step(rule.name, result.action, changes=result.changes, skipped=result.skipped)
                )
            else:
                # A whole new document from a rule written in code. Snapshotted on both sides,
                # because a later rule in the chain changes the working document in place and
                # the record must show this step as it was, not as the chain ended.
                after = self._snapshot(result, rule.name)
                before = json.loads(json.dumps(current))
                change = Change("", before, after)
                steps.append(Step(rule.name, REPLACE_DOCUMENT, changes=(change,)))
                # The chain continues on a copy of its own, so a later in-place step cannot
                # reach into whatever the rule's result shares with the rule.
                current = json.loads(json.dumps(after))

        if not steps:
            return Outcome.passthrough()
        effective = [step for step in steps if step.effective]
        if not effective:
            return Outcome(action=Action.FORWARD, message_id=message_id, steps=tuple(steps))

        original = self._parse(raw)
        if dropped:
            self._count_hits(effective)
            return Outcome(
                action=Action.DROP,
                message_id=message_id,
                original_document=original,
                steps=tuple(steps),
            )
        replacement = self._serialise(current, effective[-1].rule)
        self._count_hits(effective)
        return Outcome(
            action=Action.REPLACE,
            message_id=message_id,
            replacement=replacement,
            original_document=original,
            replacement_document=current,
            steps=tuple(steps),
        )

    def _count_hits(self, steps: list[Step]) -> None:
        # Counted after the whole chain survived serialisation: an invalid replacement is a
        # failure, not a hit, and must not inflate the number a quarantine invalidates.
        for step in steps:
            self._hits[step.rule] = self._hits.get(step.rule, 0) + 1

    @staticmethod
    def _snapshot(document: Any, rule_name: str) -> Any:
        """A detached copy of a rule's whole-document result, refused if it is not JSON."""
        try:
            return json.loads(json.dumps(document, ensure_ascii=False, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise InvalidReplacement(rule_name, "produced unserialisable output") from exc

    # -- id tracking ----------------------------------------------------------------

    @staticmethod
    def _read(raw: bytes) -> tuple[Any | None, bool, bool]:
        """The document, whether it nests deeper than
        :data:`mcp_kymograph.events.MAX_DOCUMENT_DEPTH`: then only its top level, so that its id
        is learned the same on every Python version, and whether the message was not valid
        UTF-8: then read from the text with replacement characters, as a client reads it.
        None for one that is not JSON."""
        text, valid = events.decode(raw)
        document, too_deep = events.load(text, events.MAX_DOCUMENT_DEPTH)
        return document, too_deep, not valid

    @staticmethod
    def _parse(raw: bytes) -> Any | None:
        """The document, or None for a message that is not JSON or is too deep for
        ``json.loads`` itself. Either passes through untouched."""
        text, valid = events.decode(raw)
        if not valid:
            return None
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            return None

    def _table(self, sent: Direction) -> dict[correlation.Key, str]:
        """The table of the requests sent in direction ``sent``."""
        if sent is Direction.SERVER_TO_CLIENT:
            return self._server_method_by_id
        return self._method_by_id

    def _remember_request(self, direction: Direction, document: Any) -> None:
        if not isinstance(document, dict):
            return
        method = document.get("method")
        key = correlation.key_of(document.get("id"))
        if isinstance(method, str) and key is not None and key is not correlation.AMBIGUOUS:
            table = self._table(direction)
            if len(table) >= MAX_TRACKED_IDS:
                table.clear()  # a stuck server must not grow this without bound
            table[key] = method

    def _responded_method(self, direction: Direction, document: Any) -> str | None:
        """The method of the request a message answers: looked up among the requests sent the
        other way."""
        if not isinstance(document, dict) or "method" in document:
            return None
        key = correlation.key_of(document.get("id"))
        if key is None or key is correlation.AMBIGUOUS:
            return None
        answered = (
            Direction.CLIENT_TO_SERVER
            if direction is Direction.SERVER_TO_CLIENT
            else Direction.SERVER_TO_CLIENT
        )
        return self._table(answered).get(key)

    def _serialise(self, document: dict, rule_name: str) -> bytes:
        # Validate before sending: a replacement that would not parse is a bug in the rule,
        # not something that goes out silently. json.dumps already guarantees valid JSON, so
        # this guard catches a rule returning something json cannot represent at all.
        try:
            raw = json.dumps(document, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise InvalidReplacement(rule_name, "produced unserialisable output") from exc
        try:
            json.loads(raw)
        except ValueError as exc:  # pragma: no cover - json.dumps output is always parseable
            raise InvalidReplacement(rule_name, "produced unparseable output") from exc
        return raw


def _id_of(document: Any) -> str | int | None:
    return correlation.message_id(document.get("id")) if isinstance(document, dict) else None
