"""Whether a server marks foreign content as foreign: ``engagement canary`` and ``marking``.

A server hands content it does not own (a web page, a file, a row of a database) on to a model.
The question is whether it says so. The examiner plants a canary in the foreign source before the
run (``engagement canary`` gives its value); ``engagement marking RUN`` finds where the canary
came back in the recording and states, for each such **delivery**, four properties:

* **A** the source is named in the same result;
* **B** the beginning of the foreign block is delimited;
* **C** its end is;
* **D** the block is structurally apart: a block of its own beside others in ``content``, a field
  of its own beside fields of the server in ``structuredContent``, or a resource block with a
  ``uri`` (which is D **and** A).

**The recording does not show who wrote a text, the server or the foreign content: not in the
canary's string, and not in a neighbouring one, since a server may spread foreign content over
several blocks. Text therefore never makes a delivery ``delimited``.** ``unmarked`` has none of
the four; ``delimited`` has an A from a ``uri`` (which brings D with it) and no note of doubt;
``partial`` is everything between. Only an A from a ``uri`` is *firm*: a resource block with a
``uri`` in ``content`` or in ``prompts/get``, or an entry of ``contents`` with a ``uri``. A
pattern that gives A is text, in any string, and never firm. A run is as marked as its weakest
delivery. **This is an observation, not a severity.**

D is read mechanically, from the path in the JSON. A, B and C are read against the open list of
patterns (``data/marking-patterns.yaml``); each textual match is marked ``to_confirm``: a person
reads the answer and says whether it is so, and the tool does not carry that back into the
marking. A resource block's ``uri`` is A without ``to_confirm``. A, B, C and D stay
observations and are shown; A is also true when it comes from text alone. A server that names
the source in text, in the canary's block or in the neighbouring one, stays ``partial`` with
``possibly_forged``.

**Every place is a delivery.** A canary that stands in a string more than once is one delivery
for each place (``occurrence``, from 1). A match of a pattern counts only if it ends before the
canary begins; only a closer that holds the canary ends its block all the same. A is also given
by a text pattern that matches in any string of the same result.

**Notes of doubt.** Each keeps a delivery from ``delimited``, also beside a firm A and D:

* ``broken_out``: the foreign content closed the server's block, and the server's closer is left
  over after the canary. B and C go. For the code fence "of the same kind" is read as in
  Markdown: a closing fence has the same character, is at least as long, and has nothing but
  white space after it. Backticks and tildes are read each for itself, but a block of the other
  character that was closed before the canary and has its closer left over after it is a
  breakout too.
* ``ambiguous_blocks``: two complete blocks of the same delimiter, the canary in the second or a
  later one, on the line of its opener, or between them, and no closer left over. The tool cannot
  tell two blocks of the server from one the foreign content closed and opened anew. B and C go.
* ``possibly_forged``: the delivery is not ``delimited``, and B or C comes from text in the
  canary's string and has not gone, or A comes from text in any string of the result and not
  from a ``uri``. Also beside a ``uri``, when another note keeps the delivery from
  ``delimited``. A consequence, not a cause, and no proof of a forgery.
* ``quoted``: the marking stands in a string of the text and gives no A, B and C: the whole
  string is JSON (an object, a list or a string; one nested too deeply to parse counts) or a
  whole ``repr``; or a beginning of the
  marking (any match of a label, any opener of a pair) stands before the canary in the same
  ``"…"`` literal of one line, also behind a match outside it. A string of the first kind in
  which a pattern would give A gives none, and the note stands at the delivery.
* ``encoded``: an encoded opener of a tag pair (``&lt;untrusted``, ``%3Cexternal``, …) stands
  before the canary in its string, and no whole pair gives B and C. It gives no property.

``breakout_unchecked`` is no note of doubt: the code fence keeps it (the rule does not yet check
that the foreign content did not write the fence).

**No value from a recording is ever shown**: not a canary's value, not a word of an answer. A
delivery points at the message (its ``seq``) and the path in it, and a key stands in the path only
if the MCP schema has it and it holds no canary value. Nothing is sent and nothing is written.

**Its limits** (docs/content-marking.md): a canary that the server changed is not found; the
search is for the exact string in a string of the JSON, also in a key; a payload that is no JSON
or was cut off is counted (``not_read``), not read; a server that really marks in text, in the
canary's string or in a neighbouring one, is ``partial`` all the same; a file with fences of its
own in a resource block is ``partial`` if the canary stands in its second fence, so the examiner
lays it outside them.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from bisect import bisect_left, bisect_right
from collections.abc import Iterable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any, NamedTuple

from mcp_kymograph import corpus, identity_compare, verdict
from mcp_kymograph import events as recorded
from mcp_kymograph.engagement import MIN_SALT_LENGTH
from mcp_kymograph.scenario import MAX_FILE_BYTES, ScenarioError, parse_yaml

#: The sentence every output carries.
OBSERVATION = "an observation, not a severity"

PATTERNS_RESOURCE = "marking-patterns.yaml"

UNMARKED = "unmarked"
PARTIAL = "partial"
DELIMITED = "delimited"
#: A run without any delivery has no marking at all.
NONE = "none"
#: From the weakest to the strongest.
LEVELS = (UNMARKED, PARTIAL, DELIMITED)

BREAKOUT_UNCHECKED = "breakout_unchecked"
BROKEN_OUT = "broken_out"
AMBIGUOUS_BLOCKS = "ambiguous_blocks"
POSSIBLY_FORGED = "possibly_forged"
QUOTED = "quoted"
ENCODED = "encoded"
#: The notes of doubt: each keeps a delivery from ``delimited``. ``breakout_unchecked`` is none.
DOUBTS = frozenset({BROKEN_OUT, AMBIGUOUS_BLOCKS, POSSIBLY_FORGED, QUOTED, ENCODED})

#: The opener of a tag pair, encoded: as an HTML entity, a JSON or Python escape, or URL-encoded.
#: It gives no property; standing before the canary with no whole pair around it, it is noted.
ENCODED_OPENER = re.compile(r"(?i)(?:&lt;|&#60;|&#x3c;|\\u003c|\\x3c|%3c)(?:untrusted|external)")

#: The prefix of a canary's value; 16 hex characters of the HMAC follow.
VALUE_PREFIX = "kymograph-canary-"
#: The prefix a value had before the tool was renamed. The prefix is no part of the HMAC, so the
#: 16 characters after it are the same. No value is made with it any more; but a canary planted
#: then is still where it was planted, and a recording made then holds it, so a reading under an
#: engagement file looks for each canary under both prefixes (:func:`earlier_values`).
EARLIER_VALUE_PREFIX = "polygraph-canary-"
VALUE_DIGITS = 16
#: The shortest value a canaries file may hold: a shorter one hits nearly every place of a message.
MIN_VALUE_LENGTH = 8
#: The most canaries one reading takes: the work is the values times the strings of a recording.
MAX_CANARIES = 256

#: The keys of the MCP schema (and of the JSON-RPC envelope) that may stand in a path. Any other
#: key is the server's, and is ``*``.
PATH_KEYS = identity_compare.SCHEMA_KEYS | frozenset(
    {
        "jsonrpc", "id", "method", "params", "protocolVersion", "capabilities", "serverInfo",
        "version", "instructions", "tools", "prompts", "resources", "resourceTemplates",
        "messages", "role", "uriTemplate", "inputSchema", "outputSchema", "nextCursor",
    }
)  # fmt: skip
#: Below these the keys are the server's, whatever they are called.
OPAQUE_KEYS = identity_compare.OPAQUE_KEYS | frozenset({"inputSchema", "outputSchema"})

Show = Any


class Refused(Exception):
    """The command is not to be carried out. The text names the reason and never a value."""


# -- the value of a canary ------------------------------------------------------------------


def canary_value(salt: str, engagement_id: str, canary_id: str) -> str:
    """The value of one canary: derived from the engagement's salt, the engagement and the canary,
    so it is unique per engagement and place, and says nothing a model could follow."""
    message = b"\0".join([b"canary", engagement_id.encode(), canary_id.encode()])
    digest = hmac.new(salt.encode(), message, hashlib.sha256).hexdigest()
    return VALUE_PREFIX + digest[:VALUE_DIGITS]


def checked_salt(env_name: str | None, salt: str | None) -> str:
    """The salt, or :class:`Refused`: a file that names no variable, whose variable is not set or
    is shorter than a run requires. Names the variable, never its value."""
    if env_name is None:
        raise Refused("the file names no environment variable for the salt (salt_env)")
    if not salt:
        raise Refused(f"the environment variable {env_name}, which holds the salt, is not set")
    if len(salt) < MIN_SALT_LENGTH:
        raise Refused(
            f"the environment variable {env_name}, which holds the salt, holds fewer than "
            f"{MIN_SALT_LENGTH} characters"
        )
    return salt


def too_many() -> str:
    return f"more than {MAX_CANARIES} canaries are given; one reading takes at most {MAX_CANARIES}"


def canary_values(engagement: Any, salt: str) -> dict[str, str]:
    """By ID, the value of each canary of an engagement file; at most ``MAX_CANARIES``."""
    if len(engagement.canaries) > MAX_CANARIES:
        raise Refused(too_many())
    return {item.id: canary_value(salt, engagement.id, item.id) for item in engagement.canaries}


def earlier_values(values: dict[str, str]) -> dict[str, str]:
    """By ID, each value of :func:`canary_values` as it was made under
    :data:`EARLIER_VALUE_PREFIX`."""
    return {
        name: EARLIER_VALUE_PREFIX + value.removeprefix(VALUE_PREFIX)
        for name, value in values.items()
    }


def read_values(path: Path) -> dict[str, str]:
    """``{id: value}`` from a JSON file, for a run without an engagement. The file is read up to
    ``MAX_FILE_BYTES``; at most ``MAX_CANARIES`` are taken; an ID has the form of one in an
    engagement file. A refusal never names an ID or a value."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise Refused("the canaries file cannot be read as JSON") from None
    if len(raw) > MAX_FILE_BYTES:
        raise Refused(f"the canaries file is larger than {MAX_FILE_BYTES} bytes")
    try:
        data = json.loads(raw)
    except RecursionError:
        raise Refused("the canaries file is nested too deeply to be read") from None
    except ValueError:
        raise Refused("the canaries file cannot be read as JSON") from None
    if not isinstance(data, dict) or not data:
        raise Refused("the canaries file is not a non-empty JSON object of id: value")
    if len(data) > MAX_CANARIES:
        raise Refused(too_many())
    for key, value in data.items():
        if not isinstance(value, str) or not value:
            raise Refused("the canaries file holds a value that is not a non-empty string")
        if len(value) < MIN_VALUE_LENGTH:
            raise Refused(
                f"the canaries file holds a value shorter than {MIN_VALUE_LENGTH} characters"
            )
        if not corpus._NAME.fullmatch(key):
            raise Refused(
                "the canaries file holds an id that is not 1 to 64 characters of letters, "
                "digits, '.', '_' and '-', beginning with a letter or digit"
            )
    # IDs are shown as lists with a comma between them, and no ID holds a comma: a value with one
    # could stand across two IDs of a list.
    if any("," in value for value in data.values()):
        raise Refused(
            "the canaries file holds a value with a comma, which a list of ids could show"
        )
    # An ID is shown in every output: one that holds a value would show the value.
    if any(value in key for key in data for value in data.values()):
        raise Refused("the canaries file holds an id that contains the value of a canary")
    return dict(data)


# -- the patterns ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Pattern:
    id: str
    kind: str
    supports: frozenset[str]
    notes: tuple[str, ...]
    regex: re.Pattern[str] | None = None
    open: re.Pattern[str] | None = None
    close: re.Pattern[str] | None = None


_PATTERN_KEYS = {
    "label": {"id", "kind", "supports", "notes", "regex"},
    "fence": {"id", "kind", "supports", "notes", "regex"},
    "pair": {"id", "kind", "supports", "notes", "open", "close"},
}
_REQUIRED = {"label": {"regex"}, "fence": {"regex"}, "pair": {"open", "close"}}


def load_patterns(path: str | Path | None = None) -> tuple[Pattern, ...]:
    """The pattern list: the one in the package, or ``path``. :class:`Refused` names the file and
    the place in it."""
    if path is None:
        source = PATTERNS_RESOURCE
        text = (
            resources.files("mcp_kymograph").joinpath("data", PATTERNS_RESOURCE).read_text("utf-8")
        )
    else:
        source = str(path)
        try:
            text = Path(path).read_text("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise Refused(f"{source}: cannot be read: {exc}") from None
    try:
        import yaml  # noqa: F401 - only to see whether the optional extra is there
    except ImportError:
        raise Refused(
            f"{source}: the pattern list is YAML and needs the optional dependency — "
            "pip install 'mcp-kymograph[yaml]'"
        ) from None
    try:
        data = parse_yaml(text, source=source)
    except ScenarioError as exc:
        raise Refused(str(exc)) from None
    return validate_patterns(data, source=source)


def validate_patterns(data: Any, *, source: str = "patterns") -> tuple[Pattern, ...]:
    def fail(where: str, why: str) -> Refused:
        return Refused(f"{source}: {where}: {why}")

    if not isinstance(data, dict) or set(data) != {"version", "patterns"}:
        raise fail("(top level)", "expected the keys version and patterns")
    if data["version"] != 1:
        raise fail("version", "this version reads version 1")
    if not isinstance(data["patterns"], list):
        raise fail("patterns", "must be a list")
    found: list[Pattern] = []
    seen: set[str] = set()
    for index, item in enumerate(data["patterns"]):
        where = f"patterns[{index}]"
        if not isinstance(item, dict) or item.get("kind") not in _PATTERN_KEYS:
            raise fail(where, "must be a mapping with kind label, fence or pair")
        kind = item["kind"]
        for key in item:
            if key not in _PATTERN_KEYS[kind]:
                raise fail(f"{where}.{key}", "unknown key")
        for key in sorted(_REQUIRED[kind] | {"id", "supports"}):
            if key not in item:
                raise fail(where, f"missing key {key!r}")
        name = item["id"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            raise fail(f"{where}.id", "must be a lowercase ID")
        if name in seen:
            raise fail(f"{where}.id", f"{name!r} listed twice")
        seen.add(name)
        supports = item["supports"]
        if (
            not isinstance(supports, list)
            or not supports
            or any(prop not in ("A", "B", "C") for prop in supports)
        ):
            raise fail(f"{where}.supports", "must be a list of A, B and C")
        notes = item.get("notes", [])
        if not isinstance(notes, list) or any(note != BREAKOUT_UNCHECKED for note in notes):
            raise fail(f"{where}.notes", f"may hold {BREAKOUT_UNCHECKED} only")
        compiled: dict[str, re.Pattern[str]] = {}
        for key in sorted(_REQUIRED[kind]):
            try:
                compiled[key] = re.compile(item[key])
            except (re.error, TypeError):
                raise fail(f"{where}.{key}", "is not a regular expression") from None
        found.append(Pattern(name, kind, frozenset(supports), tuple(notes), **compiled))
    return tuple(found)


# -- one delivery ---------------------------------------------------------------------------


@dataclass
class Delivery:
    canary: str
    seq: int
    #: The JSON path in the message, schema keys only.
    path: str
    #: Which place of the canary in that message and path this is, from 1.
    occurrence: int = 1
    #: How many places the canary has in that message and path.
    places: int = 1
    a: bool = False
    b: bool = False
    c: bool = False
    d: bool = False
    #: A comes from a ``uri``: the path says it, not a text. Only this A counts for ``delimited``.
    firm: bool = False
    #: The IDs of the patterns that matched: each is to be confirmed.
    to_confirm: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        return level_of(self.a, self.b, self.c, self.d, firm=self.firm, notes=self.notes)

    def to_dict(self, show: Show) -> dict[str, Any]:
        return {
            "canary": show(self.canary),
            "seq": self.seq,
            "path": self.path,
            "occurrence": self.occurrence,
            "A": self.a,
            "B": self.b,
            "C": self.c,
            "D": self.d,
            "marking": self.level,
            "to_confirm": list(self.to_confirm),
            "notes": list(self.notes),
        }

    def line(self, show: Show) -> str:
        held = "".join(
            name for name, on in (("A", self.a), ("B", self.b), ("C", self.c), ("D", self.d)) if on
        )
        place = f", place {self.occurrence}" if self.places > 1 else ""
        words = (
            f"  canary {show(self.canary)}, message {self.seq}, {self.path}{place}: {self.level}"
        )
        words += f" ({held or 'no property'})"
        if self.to_confirm:
            words += f"; to confirm: {', '.join(self.to_confirm)}"
        if self.notes:
            words += f"; {', '.join(self.notes)}"
        return words


def level_of(
    a: bool, b: bool, c: bool, d: bool, *, firm: bool = False, notes: Iterable[str] = ()
) -> str:
    """``delimited`` takes a firm A (from a ``uri``) and D and no note of doubt: text in any string
    of the result may be the foreign content's, so it never makes a delivery ``delimited``."""
    if not (a or b or c or d):
        return UNMARKED
    if firm and d and not DOUBTS.intersection(notes):
        return DELIMITED
    return PARTIAL


def weakest(levels: list[str]) -> str:
    return min(levels, key=LEVELS.index) if levels else NONE


def _names_a_source(held: dict[str, Any]) -> bool:
    """Whether ``held`` has a ``uri`` that names anything: an empty one names no source."""
    uri = held.get("uri")
    return isinstance(uri, str) and bool(uri.strip())


def _resource_block(block: Any, rest: tuple[Any, ...]) -> bool:
    """Whether the string below ``rest`` in ``block`` is the text or the blob of an embedded
    resource that has a ``uri``; its ``uri``, its ``mimeType`` and its ``_meta`` are not what the
    block delimits. The same for ``result.content[n]`` and ``result.messages[i].content``."""
    if not isinstance(block, dict) or rest not in (("resource", "text"), ("resource", "blob")):
        return False
    held = block.get("resource")
    return isinstance(held, dict) and _names_a_source(held)


def _in_content(content: Any, tokens: tuple[Any, ...]) -> tuple[bool, bool]:
    """(D, A) for the string at ``tokens`` below ``content``: a content block or a list of them."""
    several = False
    if isinstance(content, list):
        if not tokens or not isinstance(tokens[0], int) or tokens[0] >= len(content):
            return False, False
        several = len(content) > 1
        content, tokens = content[tokens[0]], tokens[1:]
    if _resource_block(content, tokens):
        return True, True
    return several, False


def _structure(root: Any, tokens: tuple[Any, ...]) -> tuple[bool, bool]:
    """(D, A) by the path alone: the place in the JSON and its neighbours, nothing of the text."""
    if not (len(tokens) >= 2 and isinstance(root, dict) and tokens[0] == "result"):
        return False, False
    result = root.get("result")
    if not isinstance(result, dict):
        return False, False
    where = tokens[1]
    if where == "content" and isinstance(result.get(where), list):
        return _in_content(result[where], tokens[2:])
    if where == "contents" and len(tokens) >= 3 and isinstance(tokens[2], int):
        blocks = result.get(where)
        if not isinstance(blocks, list) or tokens[2] >= len(blocks):
            return False, False
        block = blocks[tokens[2]]
        if (
            tokens[3:] in (("text",), ("blob",))
            and isinstance(block, dict)
            and _names_a_source(block)
        ):
            return True, True
        return len(blocks) > 1, False
    if where == "messages" and len(tokens) >= 3 and isinstance(tokens[2], int):
        listed = result.get("messages")
        if not isinstance(listed, list) or tokens[2] >= len(listed):
            return False, False
        several = len(listed) > 1
        sent = listed[tokens[2]]
        if tokens[3:4] == ("content",) and isinstance(sent, dict):
            inside, source = _in_content(sent.get("content"), tokens[4:])
            return several or inside, source
        return several, False
    if where == "structuredContent":
        # A field beside the server's fields, at any level on the way down to the string.
        node = result.get("structuredContent")
        for token in tokens[2:]:
            if isinstance(node, (dict, list)) and len(node) > 1:
                return True, False
            try:
                node = node[token]
            except (KeyError, IndexError, TypeError):
                break
    return False, False


class _Fence(NamedTuple):
    start: int
    end: int
    #: Where the line of the fence ends (its line break, or the end of the string): the info string
    #: is part of the line and is no content of the block.
    line_end: int
    char: str
    size: int
    #: Backtick fences with a backtick in the rest of the line are inline code, not a fence.
    opens: bool
    #: Nothing but white space follows on the line.
    closes: bool


@dataclass(frozen=True, slots=True)
class _Fenced:
    #: The complete blocks (opener, closer) in order; they do not overlap.
    blocks: list[tuple[_Fence, _Fence]]
    #: The start of each opener, for bisection.
    starts: list[int]
    #: Per fence character, its first complete block and the start of its last closer.
    firsts: dict[str, tuple[_Fence, _Fence, int]]
    #: Per fence character, the start of its last bare fence in no complete block's pair, at least
    #: as long as its shortest opener of a complete block: left open at the end, or content of a
    #: block never closed or of a block of the other character.
    left_over: dict[str, int]


#: A line break of Markdown: a CR, a LF or a CRLF (found at its CR). One search from the fence on,
#: never a search for each of the characters, which runs to the end of the string for each fence
#: when the other one does not occur in it.
_LINE_BREAK = re.compile(r"[\r\n]")
#: What the search for ``"…"`` literals stops at: an escape (a backslash and the character after
#: it, so ``\\"`` is no quotation mark), a quotation mark, a line break.
_LITERAL_STOP = re.compile(r'\\[^\r\n]|["\r\n]')


def _quoted(text: str) -> bool:
    """Whether the whole string, white space outside taken off, is a JSON object, list or string,
    or a whole ``repr`` (the same quotation mark first and last): a marking in it is in a string
    of the text, not around it. A string nested too deeply for ``json.loads`` counts as JSON: the
    way that fails must not give more than the one that reads. Integers stay text here, so that
    one of too many digits to convert does not end the reading before the syntax is known."""
    held = text.strip()
    if len(held) >= 2 and held[0] == held[-1] and held[0] in "'\"":
        return True
    if held[:1] not in ("{", "["):
        return False
    try:
        json.loads(held, parse_int=str)
    except RecursionError:
        return True
    except ValueError:
        return False
    return True


class _Text:
    """One string, with the matches of each pattern collected once (linear), so that each place of
    a canary in it is looked up by bisection and never searched for again."""

    def __init__(self, text: str) -> None:
        self.text = text
        self._first: dict[str, re.Match[str] | None] = {}
        self._all: dict[str, tuple[list[int], list[int]]] = {}
        self._fences: dict[str, _Fenced] = {}
        self._pairs: dict[str, tuple[list[int], list[int], list[int]]] = {}
        self._quoted: bool | None = None
        self._literals: tuple[list[int], list[int]] | None = None
        self._next_match: dict[str, tuple[int, int | None]] = {}

    @property
    def quoted(self) -> bool:
        """:func:`_quoted`, read once."""
        if self._quoted is None:
            self._quoted = _quoted(self.text)
        return self._quoted

    def literal(self, start: int, end: int) -> tuple[int, int] | None:
        """The ``"…"`` literal of one line the canary at ``start:end`` stands in, as the places of
        its pair of unescaped quotation marks, or None. The literals are collected once per string,
        in one pass, and looked up by bisection."""
        if self._literals is None:
            opens: list[int] = []
            closes: list[int] = []
            held: int | None = None
            for match in _LITERAL_STOP.finditer(self.text):
                found = match.group()
                if found == '"':
                    if held is None:
                        held = match.start()
                    else:
                        opens.append(held)
                        closes.append(match.start())
                        held = None
                elif found in "\r\n":
                    # A literal does not go past the end of its line.
                    held = None
            self._literals = (opens, closes)
        opens, closes = self._literals
        index = bisect_right(opens, start) - 1
        if index >= 0 and opens[index] < start and end <= closes[index]:
            return opens[index], closes[index]
        return None

    def quotes(
        self, key: str, regex: re.Pattern[str], literal: tuple[int, int], start: int
    ) -> bool:
        """Whether a match of ``regex`` begins inside ``literal`` before the canary at ``start``. It
        is searched for from the literal on, over the rest of the string: a match that an earlier
        one reaches into counts, and one that begins in the literal may end behind it. The next
        match is kept per pattern, so the places of a string, in order, read it once. The caller
        asks in ascending order; ``begin < held[0]`` stays as a guard, so that a call with an
        earlier literal searches again and the answer never depends on the order."""
        begin = literal[0] + 1
        held = self._next_match.get(key)
        if held is None or begin < held[0] or (held[1] is not None and held[1] < begin):
            found = regex.search(self.text, begin)
            held = (begin, None if found is None else found.start())
            self._next_match[key] = held
        return held[1] is not None and held[1] < start

    def first(self, key: str, regex: re.Pattern[str]) -> re.Match[str] | None:
        if key not in self._first:
            self._first[key] = regex.search(self.text)
        return self._first[key]

    def spans(self, key: str, regex: re.Pattern[str]) -> tuple[list[int], list[int]]:
        """The starts and the ends of every match, in order."""
        if key not in self._all:
            found = list(regex.finditer(self.text))
            self._all[key] = ([m.start() for m in found], [m.end() for m in found])
        return self._all[key]

    def pair_count(self, pattern: Pattern) -> tuple[list[int], list[int], list[int]]:
        """The delimiters of a pair read in their order: their starts, and for each place between
        them the blocks still open there (from the front: an opener opens one, a closer closes one
        if one is open) and the closers behind it that no opener behind it takes (from the back: a
        closer needs an opener, and an opener takes only a closer that follows it). Each place is
        an index into the lists by bisection. Collected once per string."""
        if pattern.id not in self._pairs:
            opens, _ = self.spans(pattern.id + "/open", pattern.open)
            closes, _ = self.spans(pattern.id + "/close", pattern.close)
            marks = sorted([(at, True) for at in opens] + [(at, False) for at in closes])
            still_open = [0]
            for _, opening in marks:
                still_open.append(still_open[-1] + 1 if opening else max(still_open[-1] - 1, 0))
            untaken = [0]
            for _, opening in reversed(marks):
                untaken.append(max(untaken[-1] - 1, 0) if opening else untaken[-1] + 1)
            untaken.reverse()
            self._pairs[pattern.id] = ([at for at, _ in marks], still_open, untaken)
        return self._pairs[pattern.id]

    def fences(self, pattern: Pattern) -> _Fenced:
        """The blocks of the string, found by one pass over its fence lines as Markdown reads
        them. With no block open, a line that can open one does. With one open, a line closes it
        only if it has the same character, is at least as long and has nothing after it but white
        space; every other line is content. A block without a closer at the end is no block.
        Collected once per string."""
        if pattern.id not in self._fences:
            text = self.text
            blocks: list[tuple[_Fence, _Fence]] = []
            loose: list[_Fence] = []
            content: list[_Fence] = []
            top: _Fence | None = None
            for match in pattern.regex.finditer(text):
                start, end = match.span()
                char = text[end - 1]
                # Only the run of fence characters counts for the size, not the indent before it.
                size = end - start if text[start] == char else len(match.group().lstrip(" "))
                stop = _LINE_BREAK.search(text, end)
                line_end = len(text) if stop is None else stop.start()
                rest = text[end:line_end]
                item = _Fence(
                    start,
                    end,
                    line_end,
                    char,
                    size,
                    char == "~" or "`" not in rest,
                    not rest or rest.isspace(),
                )
                if top is None:
                    if item.opens:
                        top = item
                elif item.closes and item.char == top.char and item.size >= top.size:
                    blocks.append((top, item))
                    # A shorter fence of the block's own character is its content and nothing else.
                    loose.extend(fence for fence in content if fence.char != top.char)
                    content.clear()
                    top = None
                elif item.closes:
                    content.append(item)
            loose.extend(content)
            if top is not None and top.closes:
                loose.append(top)
            firsts: dict[str, tuple[_Fence, _Fence, int]] = {}
            for opener, closer in blocks:
                first = firsts.get(opener.char, (opener, closer, 0))
                firsts[opener.char] = (first[0], first[1], closer.start)
            # Any of the blocks can be the one the foreign content closed, not only the first.
            shortest: dict[str, int] = {}
            for opener, _ in blocks:
                shortest[opener.char] = min(shortest.get(opener.char, opener.size), opener.size)
            left_over: dict[str, int] = {}
            for fence in loose:
                if fence.size >= shortest.get(fence.char, fence.size + 1):
                    left_over[fence.char] = max(left_over.get(fence.char, -1), fence.start)
            self._fences[pattern.id] = _Fenced(
                blocks, [opener.start for opener, _ in blocks], firsts, left_over
            )
        return self._fences[pattern.id]


class _Sources(NamedTuple):
    """Where a pattern that gives A matches in the strings of a message, by their index: at most
    two strings that are not quoted, and at most two that are. Two are enough to know whether one
    other than the canary's own is among them."""

    plain: list[int]
    quoted: list[int]


def _message_a(strings: list[str], patterns: tuple[Pattern, ...]) -> dict[str, _Sources]:
    """By ID, for each pattern that gives A, the strings of the message it matches in. Each pattern
    is tried once on a string, and no longer once it has its two of each; whether a string is
    quoted is read only for a string some pattern matches in, and only once."""
    found: dict[str, _Sources] = {}
    quoted: dict[int, bool] = {}
    for pattern in patterns:
        if "A" not in pattern.supports:
            continue
        regex = pattern.open if pattern.kind == "pair" else pattern.regex
        held = _Sources([], [])
        for index, text in enumerate(strings):
            if len(held.plain) >= 2 and len(held.quoted) >= 2:
                break
            if not regex.search(text):
                continue
            if index not in quoted:
                quoted[index] = _quoted(text)
            listed = held.quoted if quoted[index] else held.plain
            if len(listed) < 2:
                listed.append(index)
        found[pattern.id] = held
    return found


def _fence_doubt(fenced: _Fenced, start: int, end: int) -> tuple[bool, str | None]:
    """Whether a block of the fence surrounds the canary at ``start:end``, and the note of doubt
    the fences give it, if any.

    Only for a character whose first complete block ends before the canary. If a bare fence of it
    that pairs with nothing stands behind the canary and is as long as its shortest opener, the
    server's closer is left over and the foreign content broke out (``broken_out``): one left open
    at the end, or one that a block never closed or a block of the other character took as content,
    so that no block of its own character shows it. Otherwise, if a closer of that character stands
    behind the canary (the canary in a later block, in the info string of its opener, or before a
    complete block), the blocks balance and the tool cannot tell a server's blocks from ones the
    foreign content closed and opened anew (``ambiguous_blocks``)."""
    index = bisect_right(fenced.starts, start) - 1
    char = None
    if index >= 0:
        opener, closer = fenced.blocks[index]
        if opener.line_end <= start and closer.start >= end:
            char = opener.char
    doubt = None
    for other, (_, first_closer, last_closer) in fenced.firsts.items():
        if first_closer.line_end > start:
            continue
        if fenced.left_over.get(other, -1) >= end:
            return char is not None, BROKEN_OUT
        if last_closer >= end:
            doubt = AMBIGUOUS_BLOCKS
    return char is not None, doubt


def _delivery_text(
    where: _Text,
    start: int,
    end: int,
    patterns: tuple[Pattern, ...],
    sources: dict[str, _Sources],
    index: int,
    found: Delivery,
) -> None:
    """A, B and C around the canary at ``start:end`` of ``where``, the string ``index`` of the
    message, from the patterns, and the notes of doubt. A comes from any string of the message
    (``sources``) that is not quoted, and is never firm: only a ``uri`` is. B and C come from this
    string, a match counting only if it ends before the canary begins, and a closer already if it
    begins before."""
    own_ids: list[str] = []
    other_ids: set[str] = set()
    notes: list[str] = []
    own: set[str] = set()
    # A marking in the same "…" literal as the canary; a whole pair around it.
    in_quote = pair_whole = quoted_elsewhere = False
    literal = where.literal(start, end)
    for pattern in patterns:
        gives: set[str] = set()
        doubt = None
        if "A" in pattern.supports:
            plain, quoted = sources[pattern.id]
            if any(other != index for other in plain):
                # Text in a neighbouring string: A, to confirm, and as open to forgery as the
                # canary's own string.
                other_ids.add(pattern.id)
            quoted_elsewhere = quoted_elsewhere or any(other != index for other in quoted)
        if pattern.kind == "fence":
            inside, doubt = _fence_doubt(where.fences(pattern), start, end)
            if inside:
                gives |= pattern.supports - {"A"}
            if "A" in pattern.supports and where.first(pattern.id, pattern.regex):
                gives.add("A")
        else:
            label = pattern.kind == "label"
            key, regex = (
                (pattern.id, pattern.regex) if label else (pattern.id + "/open", pattern.open)
            )
            if literal is not None and where.quotes(key, regex, literal, start):
                # Any match in the canary's literal before it, also behind one outside.
                in_quote = True
                continue
            first = where.first(key, regex)
            if first and "A" in pattern.supports:
                gives.add("A")
            if first and first.end() <= start:
                if label:
                    gives |= pattern.supports - {"A"}
                else:
                    starts, _ = where.spans(pattern.id + "/close", pattern.close)
                    if starts and starts[-1] >= end:
                        gives |= pattern.supports - {"A"}
                        closing = bisect_left(starts, first.end())
                        if closing < len(starts) and starts[closing] < start:
                            # The first closer begins before the canary, also one that holds it
                            # in an attribute: the block ended there. A closer is left over if
                            # more closers behind the canary find no opener behind it than blocks
                            # are still open there.
                            places, still_open, untaken = where.pair_count(pattern)
                            place = bisect_left(places, end)
                            left_over = untaken[place] > still_open[place]
                            doubt = BROKEN_OUT if left_over else AMBIGUOUS_BLOCKS
                        else:
                            pair_whole = pair_whole or {"B", "C"} <= gives
        if not gives and doubt is None:
            continue
        own_ids.append(pattern.id)
        for note in (*pattern.notes, doubt):
            if note is not None and note not in notes:
                notes.append(note)
        own |= gives
    opener = where.first("/encoded", ENCODED_OPENER)
    encoded = opener is not None and opener.end() <= start and not pair_whole
    if (own_ids or in_quote or encoded) and where.quoted:
        # The whole string is one string of JSON or Python: what marks the canary stands in it.
        own_ids, notes, own, in_quote, encoded = [], [QUOTED], set(), False, False
    if in_quote or (quoted_elsewhere and QUOTED not in notes):
        notes.append(QUOTED)
    if encoded:
        notes.append(ENCODED)
    if BROKEN_OUT in notes or AMBIGUOUS_BLOCKS in notes:
        # The server's block was closed, or may have been: nothing delimits the canary any more.
        own -= {"B", "C"}
    found.to_confirm = [p.id for p in patterns if p.id in own_ids or p.id in other_ids]
    found.notes = notes
    textual_a = "A" in own or bool(other_ids)
    found.a = found.a or found.firm or textual_a
    found.b = "B" in own
    found.c = "C" in own
    if found.level != DELIMITED and (own & {"B", "C"} or (textual_a and not found.firm)):
        # A consequence, not a cause: the delivery is not delimited, and what a text gives may be
        # the foreign content's, in the canary's string or beside it, also beside a ``uri``. An A
        # that a ``uri`` gives as well is not the text's alone.
        found.notes.append(POSSIBLY_FORGED)


def _pairs(node: tuple[Any, ...], data: dict[Any, Any]) -> Any:
    for key, value in data.items():
        child = (node, key)
        yield child, key
        yield child, value


def _items(node: tuple[Any, ...], data: list[Any]) -> Any:
    for index, value in enumerate(data):
        yield (node, index), value


def _strings(data: Any) -> Any:
    """Every string of the JSON, with its node, in document order: the values, and the keys too (a
    key is a JSON string; its node is that of its value). A node is ``(parent, token)`` and the
    root is ``()``: one small tuple per child however deep it stands, made when the child is
    reached and gone when it is passed. :func:`_tokens` makes the path of a node that needs it."""
    stack = [iter([((), data)])]
    while stack:
        for node, value in stack[-1]:
            if isinstance(value, str):
                yield node, value
            elif isinstance(value, dict):
                stack.append(_pairs(node, value))
                break
            elif isinstance(value, list):
                stack.append(_items(node, value))
                break
        else:
            stack.pop()


def _tokens(node: tuple[Any, ...]) -> tuple[Any, ...]:
    """The path of a node of :func:`_strings`, as a tuple of tokens from the root."""
    found: list[Any] = []
    while node:
        found.append(node[1])
        node = node[0]
    return tuple(reversed(found))


def _places(text: str, value: str) -> Any:
    """The start of each place of ``value`` in ``text``, not overlapping, in order."""
    start = text.find(value)
    while start >= 0:
        yield start
        start = text.find(value, start + len(value))


def render_path(tokens: tuple[Any, ...], values: Iterable[str] = ()) -> str:
    """The path as a locator, where a key stands only if the schema has it and holds no canary
    value: a value is never shown, not even as a key the schema knows."""
    values = tuple(values)
    shown = ""
    opaque = False
    for token in tokens:
        if isinstance(token, int):
            shown += f"[{token}]"
            continue
        known = not opaque and token in PATH_KEYS and not any(value in token for value in values)
        word = token if known else "*"
        shown += f".{word}" if shown else word
        opaque = opaque or token in OPAQUE_KEYS
    # A value may reach across keys: ``content[0].text`` is made of three tokens.
    return "*" if any(value and value in shown for value in values) else shown


# -- a run ----------------------------------------------------------------------------------


@dataclass
class Marking:
    state: str
    causes: list[str]
    engagement_id: str | None
    deliveries: list[Delivery]
    not_delivered: list[str]
    not_read: int

    @property
    def level(self) -> str:
        return weakest([item.level for item in self.deliveries])

    def to_dict(self, show: Show) -> dict[str, Any]:
        return {
            "run": {"state": self.state, "causes": self.causes},
            "observation": OBSERVATION,
            "engagement": None if self.engagement_id is None else show(self.engagement_id),
            "marking": self.level,
            "deliveries": [item.to_dict(show) for item in self.deliveries],
            "not_delivered": [show(name) for name in self.not_delivered],
            "not_read": self.not_read,
        }

    def render(self, show: Show) -> str:
        note = (
            "" if self.state == verdict.COMPLETE else f" [{', '.join(self.causes)}]: not a result"
        )
        lines = [f"run: {self.state}{note}"]
        if self.engagement_id is not None:
            lines.append(f"engagement: {show(self.engagement_id)}")
        lines.append(f"marking: {self.level} ({OBSERVATION})")
        lines.append(f"deliveries: {len(self.deliveries)}")
        lines += [item.line(show) for item in self.deliveries]
        if self.not_delivered:
            lines.append("not delivered: " + ", ".join(show(name) for name in self.not_delivered))
        lines.append(f"not read: {self.not_read} message(s), not JSON or cut off")
        return "\n".join(lines) + "\n"


def load(path: Path) -> tuple[list[dict[str, Any]], str, list[str]]:
    """The events of a recording (``events.jsonl`` or its directory), the run's state and causes.
    A run that is not a result is read all the same."""
    where = path / "events.jsonl" if path.is_dir() else path
    try:
        raw = where.read_bytes()
    except OSError:
        raise Refused("the run cannot be read") from None
    events, problems = verdict.read_events(raw)
    if not events or events[0].get("type") != "run_started" or verdict.schema_problem(events):
        raise Refused("the run is not a recording this version reads")
    judged = verdict.judge(events, problems)
    return events, judged.state, judged.causes


def recorded_engagement(events: list[dict[str, Any]]) -> str | None:
    """The engagement ID the run says it was made under, or None."""
    authorization = events[0].get("authorization")
    held = authorization.get("engagement") if isinstance(authorization, dict) else None
    found = held.get("engagement_id_declared") if isinstance(held, dict) else None
    return found if isinstance(found, str) else None


def _scan_unit(
    root: Any,
    lead: tuple[Any, ...],
    seq: int,
    sought: list[tuple[str, str]],
    patterns: tuple[Pattern, ...],
    deliveries: list[Delivery],
    delivered: set[str],
    counted: dict[tuple[str, str], int],
) -> None:
    """The deliveries in one message of the server: ``root`` is the message, ``lead`` the index of
    it in a batch (empty if there is no batch), which is part of the path shown and of nothing
    else."""
    strings: list[str] = []
    here: list[tuple[int, tuple[Any, ...], str, int, int]] = []
    for node, text in _strings(root):
        for name, value in sought:
            here += [(len(strings), node, name, s, s + len(value)) for s in _places(text, value)]
        strings.append(text)
    if not here:
        return
    # All places of a string in ascending order, whatever the order of the values: the matches in
    # it are then read once (:meth:`_Text.quotes`). ``occurrence`` stays right, each canary's
    # places in a path still come in order.
    here.sort(key=lambda place: (place[0], place[3]))
    sources = _message_a(strings, patterns)
    # Only a string that holds a canary gets its text read, its path made and its place in the
    # structure looked up.
    held: dict[int, tuple[_Text, str, bool, bool]] = {}
    for index, node, name, start, end in here:
        delivered.add(name)
        if index not in held:
            tokens = _tokens(node)
            held[index] = (
                _Text(strings[index]),
                render_path(lead + tokens, [value for _, value in sought]),
                *_structure(root, tokens),
            )
        item, path, d, a = held[index]
        counted[(name, path)] = counted.get((name, path), 0) + 1
        found = Delivery(name, seq, path, counted[(name, path)])
        # A ``uri`` is a firm A: the path says it, not the text.
        found.d, found.a, found.firm = d, a, a
        _delivery_text(item, start, end, patterns, sources, index, found)
        deliveries.append(found)


def scan(
    events: list[dict[str, Any]],
    values: dict[str, str],
    patterns: tuple[Pattern, ...],
    earlier: dict[str, str] | None = None,
) -> tuple[list[Delivery], list[str], int]:
    """The deliveries, the IDs of the canaries with none, and how many messages of the server
    were not read (no JSON, or cut off). One delivery is one place of one canary in one string of
    one message; a string that holds it ten thousand times is read once. ``earlier`` gives, by
    ID, a second value of a canary (:func:`earlier_values`): a place of either is a delivery of
    that canary."""
    sought = [*values.items(), *(earlier or {}).items()]
    deliveries: list[Delivery] = []
    delivered: set[str] = set()
    not_read = 0
    for event in events:
        if (
            event.get("type") != "message"
            or event.get("direction") != recorded.Direction.SERVER_TO_CLIENT.value
        ):
            continue
        payload = event.get("payload")
        seq = event.get("seq")
        if not isinstance(payload, dict) or isinstance(seq, bool) or not isinstance(seq, int):
            not_read += 1
            continue
        if payload.get("encoding") != "json" or event.get("truncated") or event.get("incomplete"):
            not_read += 1
            continue
        data = payload.get("data")
        first_new = len(deliveries)
        counted: dict[tuple[str, str], int] = {}
        # A batch is a list of messages: each element is a result of its own, for D and for A.
        if isinstance(data, list):
            units = [((index,), element) for index, element in enumerate(data)]
        else:
            units = [((), data)]
        for lead, root in units:
            _scan_unit(root, lead, seq, sought, patterns, deliveries, delivered, counted)
        for found in deliveries[first_new:]:
            found.places = counted[(found.canary, found.path)]
    deliveries.sort(key=lambda item: (item.seq, item.path, item.canary, item.occurrence))
    return deliveries, [name for name in values if name not in delivered], not_read


def read(
    path: Path,
    values: dict[str, str],
    patterns: tuple[Pattern, ...],
    *,
    engagement_id: str | None = None,
    earlier: dict[str, str] | None = None,
) -> Marking:
    """``engagement marking``: the recording read, nothing sent, nothing written.

    With ``engagement_id`` (the values come from that engagement's file) the run must say it was
    made under that engagement: the values of another would be searched for in vain, and the
    result would read as ``not_delivered``. ``earlier`` is passed on to :func:`scan`.
    """
    events, state, causes = load(path)
    if engagement_id is not None and recorded_engagement(events) != engagement_id:
        raise Refused("the run was not made under this engagement")
    deliveries, missing, not_read = scan(events, values, patterns, earlier)
    return Marking(state, causes, engagement_id, deliveries, missing, not_read)
