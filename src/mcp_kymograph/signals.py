"""The signal library: named checks for content a model could read as instruction.

A **signal** is one deterministic, model-free check on the text of one field, under a stable
ID. The ID is what everything downstream names: an ``observation`` from the built-in walk, a
scenario statement that asks for it, a ``finding`` entry keyed on it. Nothing outside this
module brings a matcher of its own — a statement picks signals by ID and a place to look, and
that is all it can say.

**Two views of one string.** Every signal looks at the text through one of these:

* ``RAW`` — exactly what arrived. The *form* signals live here: an invisible character, a
  hidden comment, a run of padding are what normalisation takes away, so looking for them
  afterwards would be looking for nothing.
* ``CONTENT`` — the raw text first, then the normalised one (:func:`normalize`). The *content*
  signals live here: "ignore previous instructions" split by a zero-width space, spelled in
  full-width letters, wrapped in entities or tucked into a base64 block is the same sentence,
  and one signal should catch all of those spellings rather than one regex each.

**Normalisation only ever adds.** A content signal that matches the raw text is reported
whatever normalisation makes of it — peeling markup can join two words that were apart, and
that must not cost a hit the raw text plainly shows. A hit that exists *only* in the
normalised view is reported as such (``normalized: true`` on the event), so a reader who looks
at the recorded message and cannot see the sentence knows why it was reported.

**Three reaches.** A signal says where the built-in walk applies it: on every surface, only on
the surfaces a server writes about itself, or never — ``DECLARED`` signals fire only where a
scenario statement names them. Everything added on 2026-10-04 is ``DECLARED``: imperatives,
second-person address, URLs, base64 blocks and hidden HTML are all ordinary somewhere in an
honest server, and the walk's false-alarm floor is zero. A statement
is the author saying "here, this is worth writing down", which the walk cannot say for them.

Every pattern here runs in time linear in the text — no nested quantifiers, and no pattern
that can start a long scan at every position — because the text it runs over arrives from the
traffic under test. A bounded repetition is not enough by itself: started at every position,
it reads up to its bound each time. Where a regular expression could not say a shape in linear
time, a small scanner says it (:func:`_comment_bodies`).
"""

from __future__ import annotations

import binascii
import html
import re
import unicodedata
from base64 import b64decode
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from typing import Any
from urllib.parse import unquote


class Signal(str, Enum):
    """The signal IDs. Named for the shape, never for its consequence."""

    INVISIBLE_CHARACTERS = "invisible_characters"
    CHAT_TEMPLATE_MARKER = "chat_template_marker"
    INSTRUCTION_OVERRIDE = "instruction_override"
    CONCEALMENT_DIRECTIVE = "concealment_directive"
    OUTPUT_DIRECTIVE = "output_directive"
    MODEL_ADDRESSED = "model_addressed"
    HIDDEN_COMMENT = "hidden_comment"
    ROLE_LINE = "role_line"
    WHITESPACE_PADDING = "whitespace_padding"
    # Declared only: a statement has to ask for these.
    IMPERATIVE = "imperative"
    SECOND_PERSON = "second_person"
    EMBEDDED_URL = "embedded_url"
    BASE64_BLOCK = "base64_block"
    HIDDEN_HTML = "hidden_html"
    TOOL_NAME_DUPLICATE = "tool_name_duplicate"
    TOOL_NAME_LOOKALIKE = "tool_name_lookalike"
    # Set by the inspector alone: not a property of a text at a path, so no definition, no walk,
    # and no statement may name it.
    LONE_SURROGATE = "lone_surrogate"

    @property
    def kind(self) -> Kind:
        """What one hit of this signal is: :data:`KINDS`."""
        return KINDS[self]


class Kind(str, Enum):
    """What one hit of a signal is (docs/design/repeated-runs.md 4.1).

    *Evidence*: the hit is the recorded fact the signal stands for, and a server whose behaviour
    does not have it never produces it. *Heuristic*: the hit is a shape that harmless content has
    too, so a server can produce it now and then without what the shape is looked for being
    there. A reader of a finding needs to know which, to know which rows can fire on honest
    content; the kind says that and nothing more — it is no severity and no verdict.
    """

    EVIDENCE = "evidence"
    HEURISTIC = "heuristic"


#: Every signal's kind, as repeated-runs.md 4.1 reads it from the code. One entry per signal,
#: none left to a default (a test holds it so): a signal added without a kind is a mistake to
#: find, not a heuristic by accident.
KINDS: dict[Signal, Kind] = {
    Signal.INVISIBLE_CHARACTERS: Kind.HEURISTIC,
    Signal.CHAT_TEMPLATE_MARKER: Kind.HEURISTIC,
    Signal.INSTRUCTION_OVERRIDE: Kind.HEURISTIC,
    Signal.CONCEALMENT_DIRECTIVE: Kind.HEURISTIC,
    Signal.OUTPUT_DIRECTIVE: Kind.HEURISTIC,
    Signal.MODEL_ADDRESSED: Kind.HEURISTIC,
    Signal.HIDDEN_COMMENT: Kind.HEURISTIC,
    Signal.ROLE_LINE: Kind.HEURISTIC,
    Signal.WHITESPACE_PADDING: Kind.HEURISTIC,
    Signal.IMPERATIVE: Kind.HEURISTIC,
    Signal.SECOND_PERSON: Kind.HEURISTIC,
    Signal.EMBEDDED_URL: Kind.HEURISTIC,
    Signal.BASE64_BLOCK: Kind.HEURISTIC,
    Signal.HIDDEN_HTML: Kind.HEURISTIC,
    # An identical name twice in one listing, compared character for character as sent.
    Signal.TOOL_NAME_DUPLICATE: Kind.EVIDENCE,
    # Names a person reads alike but written differently: get_user and getUser can both exist.
    Signal.TOOL_NAME_LOOKALIKE: Kind.HEURISTIC,
    # Set by the inspector alone, from the announced name as it arrived.
    Signal.LONE_SURROGATE: Kind.EVIDENCE,
}


class View(Enum):
    RAW = "raw"
    CONTENT = "content"
    #: Compares a tool name against the other names in the same listing.
    NAME = "name"


class Reach(Enum):
    """Where the built-in walk applies a signal. A statement applies it wherever it points."""

    EVERYWHERE = "everywhere"
    METADATA = "metadata"
    DECLARED = "declared"


class Via(str, Enum):
    """Which view a signal fired on. ``NORMALIZED`` means the raw text alone did not."""

    RAW = "raw"
    NORMALIZED = "normalized"


# -- normalisation ------------------------------------------------------------------------

#: Zero-width and formatting characters with no visible mark.
ZERO_WIDTH = frozenset("\u200b\u2060\ufeff\u00ad\u180e")

#: Joiners that are load-bearing in emoji sequences and in Indic and Arabic scripts.
JOINERS = frozenset("\u200c\u200d")

#: Bidirectional overrides and isolates: they reorder what a person sees without changing
#: what a parser reads.
BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

TAG_BLOCK = range(0xE0000, 0xE0080)

#: Everything the normalised view drops outright. Joiners too: the content signals look for
#: English sentences, and an emoji sequence losing its joiner in a view no one reads costs
#: nothing.
_STRIP = dict.fromkeys(
    [ord(c) for c in ZERO_WIDTH | JOINERS | BIDI] + list(TAG_BLOCK),
    None,
)

#: The normalised view may grow — NFKC expands some characters many times over — but not
#: without end: it is matched on the event loop. Past this it is cut, and the cut is
#: reported as a bounded inspection rather than passed off as a full one.
NORMALIZED_GROWTH = 2
NORMALIZED_SLACK = 1024

#: A base64 run shorter than this decodes to fewer than 18 bytes: too short to carry a
#: sentence, and long enough to be an ordinary identifier.
MIN_BASE64_CHARS = 24
MAX_BASE64_BLOCKS = 8
#: A base64 run longer than this is decoded only up to here, and counts as cut.
MAX_BASE64_CHARS = 65536

# No upper bound in the pattern: a run past MAX_BASE64_CHARS must still be found, or it would
# be skipped without a trace. The lookbehind keeps every start at the head of a run, so the
# scan stays linear.
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")

# HTML tags by name. Only names HTML actually has: a generic "<word ...>" would also eat
# "<<SYS>>", which the chat-template signal needs to see, and "<id>" placeholders in prose.
_HTML_TAG_NAMES = (
    "a|abbr|b|big|blockquote|br|center|cite|code|del|details|dfn|div|em|font|h[1-6]|hr|i|img"
    "|ins|kbd|label|li|mark|ol|p|pre|q|s|samp|small|span|strike|strong|sub|summary|sup|table"
    "|tbody|td|th|thead|tr|tt|u|ul|var"
)
_HTML_TAG = re.compile(rf"</?(?:{_HTML_TAG_NAMES})\b[^<>]{{0,500}}>", re.IGNORECASE)
_COMMENT_SHELL = re.compile(r"<!--|-->")
_LINE_MARKUP = re.compile(r"^[ \t]{0,3}(?:#{1,6}|>)[ \t]?", re.MULTILINE)
_INLINE_MARKUP = str.maketrans("", "", "*_~`")
_SPACES = re.compile(r"[ \t\f\v]+")
_BLANK_LINES = re.compile(r"\n(?: ?\n)+")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_URLSAFE = str.maketrans("-_", "+/")

#: A numeric character reference with more significant digits than this is past U+10FFFF
#: whatever follows (decimal: at least 10**7, hex: at least 0x10000000), and ``html.unescape``
#: turns it into U+FFFD. Eight is the most digits a valid code point needs (``10ffff`` is six,
#: ``1114111`` seven) with one to spare, and everything longer is the same replacement.
MAX_CHARREF_DIGITS = 8

# The digits of a numeric reference, taken greedily as ``html`` takes them, when there are more
# than the bound. Only ASCII digits, as in ``html``'s own expression. A match starts only at
# "&#", and a try that fails has read at most the bound of digits, so the scan stays linear.
_LONG_CHARREF = re.compile(
    rf"&#(?:(?P<dec>[0-9]{{{MAX_CHARREF_DIGITS + 1},}})"
    rf"|(?P<hex>[xX][0-9a-fA-F]{{{MAX_CHARREF_DIGITS + 1},}}))"
)


def _shorten_charref(match: re.Match[str]) -> str:
    digits = match.group("dec")
    prefix = "&#"
    if digits is None:
        prefix += match.group("hex")[0]
        digits = match.group("hex")[1:]
    return prefix + (digits.lstrip("0") or "0")[:MAX_CHARREF_DIGITS]


def _shorten_charrefs(text: str) -> str:
    """Long numeric references cut to what ``html.unescape`` makes of them, nothing else."""
    return _LONG_CHARREF.sub(_shorten_charref, text)


def _flatten(text: str) -> str:
    """One string through every normalisation step except base64, in a fixed order.

    Decoding comes first because what it produces can need every later step: an entity can
    spell a zero-width space, a percent sequence a full-width letter. Each step runs once —
    a doubly encoded sentence stays encoded once, which is a stated limit, not an oversight.
    A long numeric reference is shortened first to an equal one, because Python does not turn
    a long run of digits into a number.
    """
    if "&" in text:
        text = html.unescape(_shorten_charrefs(text))
    if _PERCENT.search(text):
        text = unquote(text)
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_STRIP)
    # Peel markup. A comment's shell goes and its body stays: what is inside a comment is
    # text a model reads, and it is exactly the text worth matching.
    text = _COMMENT_SHELL.sub(" ", text)
    text = _HTML_TAG.sub("", text)
    text = _LINE_MARKUP.sub("", text)
    text = text.translate(_INLINE_MARKUP)
    text = _SPACES.sub(" ", text)
    return _BLANK_LINES.sub("\n", text)


def _base64_blocks(text: str) -> Iterator[tuple[str | None, bool]]:
    """Each base64 run as (decoded or None, whether the run was longer than the bound)."""
    found = 0
    for match in _BASE64.finditer(text):
        start, end = match.start(), match.end()
        while text[end - 1] == "=":
            end -= 1
        long = end - start > MAX_BASE64_CHARS
        if found >= MAX_BASE64_BLOCKS:
            # A run past the bound on blocks is not looked at: that is a cut, long or short.
            # Otherwise eight harmless readable blocks would hide a ninth. Only readable blocks
            # count toward the bound, so ordinary base64 ids (binary when decoded) cut nothing.
            yield None, True
            return
        # Slice the text, not the match: at most MAX_BASE64_CHARS characters are copied.
        block = text[start : start + MAX_BASE64_CHARS] if long else text[start:end]
        block = block.translate(_URLSAFE)
        if len(block) % 4 == 1:
            yield None, long
            continue
        block += "=" * (-len(block) % 4)
        try:
            decoded = b64decode(block, validate=True).decode("utf-8")
        except (binascii.Error, ValueError):
            yield None, long
            continue
        if not decoded or not all(c.isprintable() or c in "\n\r\t" for c in decoded):
            yield None, long
            continue
        if not any(c.isalpha() for c in decoded):
            yield None, long
            continue
        found += 1
        yield decoded, long


def base64_texts(text: str) -> Iterable[str]:
    """Every base64 run in the text that decodes to readable UTF-8, decoded.

    Readable means: valid UTF-8, nothing but printable characters and line breaks, and at
    least one letter. Random binary passes that by accident at 18 bytes about never, and an
    identifier that happens to be valid base64 decodes to binary, not to text.

    A run longer than MAX_BASE64_CHARS is not skipped: its first MAX_BASE64_CHARS characters
    (cut to a multiple of four) are decoded and checked like any block. `normalize` reports
    such a run as a cut.
    """
    for decoded, _ in _base64_blocks(text):
        if decoded is not None:
            yield decoded


def normalize(text: str) -> tuple[str, bool]:
    """The normalised view of a string, and whether the growth bound cut it short.

    NFKC, invisible characters stripped, HTML entities and percent-encoding decoded, HTML and
    markdown peeled, whitespace collapsed — and every readable base64 block in the raw text
    decoded and appended on a line of its own, normalised the same way. One level: a base64
    block inside a base64 block is not opened.

    A base64 run longer than MAX_BASE64_CHARS is decoded only up to that bound, and the result
    is reported as cut even when the start is not readable: the rest was not looked at.

    The pieces are joined by line breaks, and every content pattern stops at a line break,
    so no match can straddle the text and something decoded out of it.
    """
    pieces = [_flatten(text)]
    cut = False
    for decoded, long in _base64_blocks(text):
        cut = cut or long
        if decoded is not None:
            pieces.append(_flatten(decoded))
    joined = "\n".join(pieces)
    limit = NORMALIZED_GROWTH * len(text) + NORMALIZED_SLACK
    if len(joined) > limit:
        return joined[:limit], True
    return joined, cut


# -- tool names ---------------------------------------------------------------------------

#: Letters from other scripts that are drawn like a Latin one. Not the whole Unicode
#: confusables table — the common Cyrillic and Greek lookalikes, which is what a spoofed tool
#: name reaches for first. Applied after casefolding, so lower case is enough.
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043a": "k",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u0458": "j",
        "\u0455": "s",
        "\u0501": "d",
        "\u04cf": "l",
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bd": "v",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c7": "x",
    }
)


def name_key(name: str) -> str:
    """What a tool name reads as to a person: no case, no separators, no lookalikes.

    ``read_file``, ``Read-File``, ``readFile`` and ``re\u0430d_file`` with a Cyrillic ``\u0430`` all
    come out as ``readfile``.
    """
    folded = unicodedata.normalize("NFKC", name).translate(_STRIP).casefold()
    return "".join(c for c in folded.translate(_CONFUSABLES) if c.isalnum())


@dataclass(frozen=True, slots=True)
class NameIndex:
    """The tool names of one listing, counted as written and as read."""

    written: Counter[str]
    read: Counter[str]

    @classmethod
    def of(cls, document: Any) -> NameIndex:
        names = [
            tool["name"]
            for tool in _tools(document)
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        ]
        return cls(Counter(names), Counter(name_key(name) for name in names))


EMPTY_NAMES = NameIndex(Counter(), Counter())


def _tools(document: Any) -> list:
    result = document.get("result") if isinstance(document, dict) else None
    tools = result.get("tools") if isinstance(result, dict) else None
    return tools if isinstance(tools, list) else []


# -- the subject --------------------------------------------------------------------------


class Subject:
    """One string under test. Its normalised view is computed once, and only if asked for."""

    __slots__ = ("raw", "_names", "_normalized", "_cut", "_long_run")

    def __init__(self, raw: str, names: Callable[[], NameIndex] | None = None) -> None:
        self.raw = raw
        self._names = names
        self._normalized: str | None = None
        self._cut = False
        self._long_run: bool | None = None

    @property
    def normalized(self) -> str:
        if self._normalized is None:
            self._normalized, self._cut = normalize(self.raw)
        return self._normalized

    @property
    def cut(self) -> bool:
        """Whether the normalised view was computed and a bound shortened it, or the raw text
        holds a base64 run longer than :data:`MAX_BASE64_CHARS`: such a run is cut wherever it
        is read, also by a signal that never asks for the normalised view (``base64_block``)."""
        if self._cut:
            return True
        if self._long_run is None:
            self._long_run = any(
                len(match.group(0).rstrip("=")) > MAX_BASE64_CHARS
                for match in _BASE64.finditer(self.raw)
            )
        return self._long_run

    def names(self) -> NameIndex:
        return self._names() if self._names is not None else EMPTY_NAMES


# -- the form signals ---------------------------------------------------------------------

#: An HTML comment has to be complete and have something in it before it counts.
#:
#: *Complete*, because a lone ``<!--`` is as likely to be prose about HTML as a hidden span.
#: *Non-trivial*, because calibration turned up the other half of the same problem: a
#: description that documents markup ("Matches an HTML comment: <!-- and --> are both
#: required") contains a real, complete, empty comment and is not hiding anything. A carrier
#: for an instruction is a sentence; this is the shortest one worth calling a sentence.
MIN_COMMENT_BODY = 12

#: The longest comment body looked at; a ``<!--`` with no ``-->`` within this many characters
#: after it opens no comment.
MAX_COMMENT_BODY = 4000


def _comment_bodies(text: str) -> Iterator[str]:
    """The bodies of the HTML comments in ``text``: from each ``<!--``, up to the first ``-->``
    within :data:`MAX_COMMENT_BODY` characters, scanning on behind each one found.

    What ``<!--(.{0,4000}?)-->`` with ``re.DOTALL`` finds, without its cost: that expression
    reads up to 4000 characters for every ``<!--`` that has no end, so a text made of nothing
    but ``<!--`` costs four thousand reads per character. Here a stretch already searched in
    vain is remembered and not searched again, so every character is read a small, fixed
    number of times.
    """
    searched = 0  # no "-->" starts anywhere from the current body's start up to here
    opening = text.find("<!--")
    while opening != -1:
        start = opening + 4
        stop = start + MAX_COMMENT_BODY + 3
        closing = text.find("-->", max(start, searched), stop)
        if closing == -1:
            searched = max(searched, stop - 2)
            opening = text.find("<!--", opening + 1)
        else:
            yield text[start:closing]
            opening = text.find("<!--", closing + 3)


# The two markdown comment idioms that render to nothing. Anchored at the start of a line and
# spelled exactly, so an ordinary reference link (``[docs]: https://…``) is not swept up.
_MARKDOWN_COMMENT = re.compile(r"^[ \t]{0,3}\[(?://|comment)\]:[ \t]", re.MULTILINE)


def _has_hidden_comment(text: str) -> bool:
    if _MARKDOWN_COMMENT.search(text):
        return True
    return any(len(body.strip()) >= MIN_COMMENT_BODY for body in _comment_bodies(text))


def _has_invisible(text: str) -> bool:
    """Whether the string carries a character a reader cannot see.

    Three narrowings, each because the character has an innocent life elsewhere: a leading
    U+FEFF is a byte-order mark, and U+200C/U+200D are required by emoji sequences and by
    several scripts, so they count only between ASCII where they cannot be doing that.
    """
    for index, character in enumerate(text):
        if character in BIDI:
            return True
        if character in ZERO_WIDTH:
            if character == "\ufeff" and index == 0:
                continue
            return True
        if character in JOINERS and _between_ascii(text, index):
            return True
        if ord(character) in TAG_BLOCK:
            return True
    return False


def _between_ascii(text: str, index: int) -> bool:
    before = text[index - 1] if index > 0 else " "
    after = text[index + 1] if index + 1 < len(text) else " "
    return before.isascii() and after.isascii()


# Content pushed out of sight by blank lines or a long run of spaces.
_PADDING = re.compile(r"\n[ \t]{0,20}\n[ \t]{0,20}\n|[ \t]{30,}")

# An HTML element a browser would not draw: the ``hidden`` attribute, or a style that hides
# it. ``aria-hidden`` is not one — it hides from a screen reader, not from the eye.
_ANY_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9-]{0,30}(?:\s[^<>]{0,1000})?>")
_HIDING = re.compile(
    r"(?<![-\w])hidden\b"
    r"|display\s{0,4}:\s{0,4}none"
    r"|visibility\s{0,4}:\s{0,4}hidden"
    r"|(?:font-size|width|height|max-height)\s{0,4}:\s{0,4}0(?:\.0{1,8})?(?![.\d])"
    r"|opacity\s{0,4}:\s{0,4}0(?:\.0{1,8})?(?![.\d])",
    re.IGNORECASE,
)


def _has_hidden_html(text: str) -> bool:
    return any(_HIDING.search(tag.group(0)) for tag in _ANY_TAG.finditer(text))


def _has_base64_text(text: str) -> bool:
    return next(iter(base64_texts(text)), None) is not None


# -- the content signals ------------------------------------------------------------------

# Chat-template framing. These strings exist only inside a model's prompt format; a server
# has no other reason to emit one, whatever it is carrying.
_CHAT_TEMPLATE = re.compile(
    r"<\|(?:im_start|im_end|im_sep|endoftext|start_header_id|end_header_id|eot_id"
    r"|system|user|assistant)\|>"
    r"|\[/?INST\]"
    r"|<</?SYS>>",
    re.IGNORECASE,
)

# A conversation turn faked at the start of a line. Metadata only: in a document a tool
# returned, "System:" is a transcript, a log line or a table cell.
_ROLE_LINE = re.compile(r"(?:^|\n)[ \t]{0,8}(?:assistant|system|user|human)[ \t]{0,4}:", re.I)

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass|set aside)\b[^.\n]{0,40}"
    r"\b(?:previous|prior|earlier|above|preceding|all|any|your|the|these|those)\b[^.\n]{0,30}"
    r"\b(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions"
    r"|guideline|guidelines|system message|context)\b",
    re.IGNORECASE,
)

# The tell is the possessive: server-supplied text speaking about "your reply".
_OUTPUT_DIRECTIVE = re.compile(
    r"\b(?:append|prepend|insert|include|add|output|print|emit|repeat|echo|end|begin|start)\b"
    r"[^.\n]{0,60}\byour\s+(?:reply|response|answer|output|message)\b"
    r"|\byour\s+(?:reply|response|answer|output|message)\b[^.\n]{0,40}"
    r"\b(?:must|should|has to|needs to)\b[^.\n]{0,30}"
    r"\b(?:contain|include|append|end with|start with|begin with)\b",
    re.IGNORECASE,
)

# Hiding an action from the person is the move; the addressee is what makes it one, so it is
# required. Without it, "do not display binary output" would read as concealment.
_CONCEALMENT = re.compile(
    r"\b(?:do not|don't|never|avoid|refrain from)\b[^.\n]{0,40}"
    r"\b(?:mention|tell|reveal|disclose|inform|notify|show|report|explain|acknowledge"
    r"|display|say)\b[^.\n]{0,30}\b(?:user|users|human|operator|anyone|caller|client|them)\b"
    r"|\bwithout\s+(?:telling|informing|notifying|alerting|asking|mentioning (?:it )?to)\b"
    r"[^.\n]{0,20}\b(?:the\s+)?(?:user|human|operator|anyone|caller)\b"
    r"|\bkeep\s+(?:this|it|that)\s+(?:secret|hidden|private|to yourself|between us)\b",
    re.IGNORECASE,
)

# Text that names the model as its reader. A plain imperative is deliberately *not* here:
# "Use this tool when the user asks about the weather" is how tool descriptions are written,
# and a checker that fired on it would fire on almost every real server.
#
# Two narrowings that calibration forced, both because the word is ordinary domain
# vocabulary in an honest description:
#
# * bare "model" and bare "agent" are out of the directive branch — "the agent will retry
#   failed requests" and "the model name to use" are field descriptions, not addressees.
#   "ai agent" and "ai model" stay, because the qualifier is what makes it an address.
# * "will" is out of the modal list: it is the descriptive future far more often than an
#   instruction.
_MODEL_ADDRESSED = re.compile(
    r"\b(?:you are|you're|as|if you are|if you're)\s+(?:an?\s+)?"
    r"(?:ai|a\.i\.|artificial intelligence|language model|llm|assistant|agent|chatbot|bot)\b"
    r"|\b(?:ai|llm|language model|ai agents?|ai models?|assistant|chatbot)s?\b[^.\n]{0,20}"
    r"\b(?:must|should|shall|need to|needs to|have to|has to|are required to"
    r"|is required to|are instructed to|is instructed to)\b"
    r"|\b(?:attention|note to|notes to|instructions? for|instructions? to|message to|dear)\s+"
    r"(?:the\s+)?(?:ai|llm|assistant|agent|model|language model)\b",
    re.IGNORECASE,
)

# A sentence that opens on a command verb. Declared only: this is the style nearly every
# honest tool description is written in, and the walk deliberately ignores it (15.1).
_IMPERATIVE = re.compile(
    r"(?:^|[.!?;:]\s{1,8}|\n)[ \t]{0,8}(?:please[ \t]{1,4})?"
    r"(?:always|never|do not|don't|make sure|ensure|remember|ignore|disregard|forget|use|call"
    r"|invoke|run|execute|send|post|upload|read|write|fetch|open|include|append|prepend|insert"
    r"|return|output|print|reply|respond|answer|say|tell|show|delete|remove|copy|forward|email"
    r"|summari[sz]e|first|then|instead|stop|continue|proceed)\b",
    re.IGNORECASE,
)

# "You" told what to do, or told what its task is. Declared only: "You must provide a valid
# project id" is an honest field description.
_SECOND_PERSON = re.compile(
    r"\byou\s{1,4}(?:must|should|shall|need\s{1,4}to|have\s{1,4}to|will\s{1,4}now"
    r"|may\s{1,4}not|cannot|can't|always|never)\b"
    r"|\byou(?:'re|\s{1,4}are)\s{1,4}(?:required|instructed|expected|not\s{1,4}allowed|now)\b"
    r"|\byour\s{1,4}(?:task|job|instructions?|goal|role|purpose|objective|mission)\b",
    re.IGNORECASE,
)

_URL = re.compile(
    r"\b(?:https?|ftps?|file|wss?)://[^\s<>\"'`]{1,2048}"
    r"|\b(?:data|javascript|vbscript):[^\s<>\"'`]{1,2048}"
    r"|\bwww\.[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,24}\b",
    re.IGNORECASE,
)


def _searcher(compiled: re.Pattern[str]) -> Callable[[str], bool]:
    def test(text: str) -> bool:
        return compiled.search(text) is not None

    return test


# -- the library --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Definition:
    """One library entry: the ID, which view it reads, how far the walk takes it, the test."""

    signal: Signal
    view: View
    reach: Reach
    test: Callable[[str], bool] | None = None


#: The library, in the order signals are reported for one string.
LIBRARY: tuple[Definition, ...] = (
    Definition(Signal.INVISIBLE_CHARACTERS, View.RAW, Reach.EVERYWHERE, _has_invisible),
    Definition(
        Signal.CHAT_TEMPLATE_MARKER, View.CONTENT, Reach.EVERYWHERE, _searcher(_CHAT_TEMPLATE)
    ),
    Definition(Signal.INSTRUCTION_OVERRIDE, View.CONTENT, Reach.EVERYWHERE, _searcher(_OVERRIDE)),
    Definition(
        Signal.CONCEALMENT_DIRECTIVE, View.CONTENT, Reach.EVERYWHERE, _searcher(_CONCEALMENT)
    ),
    Definition(
        Signal.OUTPUT_DIRECTIVE, View.CONTENT, Reach.EVERYWHERE, _searcher(_OUTPUT_DIRECTIVE)
    ),
    Definition(Signal.MODEL_ADDRESSED, View.CONTENT, Reach.EVERYWHERE, _searcher(_MODEL_ADDRESSED)),
    Definition(Signal.HIDDEN_COMMENT, View.RAW, Reach.METADATA, _has_hidden_comment),
    Definition(Signal.ROLE_LINE, View.CONTENT, Reach.METADATA, _searcher(_ROLE_LINE)),
    Definition(Signal.WHITESPACE_PADDING, View.RAW, Reach.METADATA, _searcher(_PADDING)),
    Definition(Signal.IMPERATIVE, View.CONTENT, Reach.DECLARED, _searcher(_IMPERATIVE)),
    Definition(Signal.SECOND_PERSON, View.CONTENT, Reach.DECLARED, _searcher(_SECOND_PERSON)),
    Definition(Signal.EMBEDDED_URL, View.CONTENT, Reach.DECLARED, _searcher(_URL)),
    Definition(Signal.BASE64_BLOCK, View.RAW, Reach.DECLARED, _has_base64_text),
    Definition(Signal.HIDDEN_HTML, View.RAW, Reach.DECLARED, _has_hidden_html),
    Definition(Signal.TOOL_NAME_DUPLICATE, View.NAME, Reach.DECLARED),
    Definition(Signal.TOOL_NAME_LOOKALIKE, View.NAME, Reach.DECLARED),
)

BY_SIGNAL: dict[Signal, Definition] = {definition.signal: definition for definition in LIBRARY}

#: What the built-in walk applies, per kind of surface, in library order.
WALK_METADATA: tuple[Signal, ...] = tuple(
    d.signal for d in LIBRARY if d.reach in (Reach.EVERYWHERE, Reach.METADATA)
)
WALK_CONTENT: tuple[Signal, ...] = tuple(d.signal for d in LIBRARY if d.reach is Reach.EVERYWHERE)


def check(signal: Signal, subject: Subject) -> Via | None:
    """Whether one signal fires on one subject, and on which view."""
    definition = BY_SIGNAL[signal]
    if definition.view is View.NAME:
        return _NAME_RULES[signal](subject)
    assert definition.test is not None  # noqa: S101 - every non-NAME entry carries a test
    if definition.test(subject.raw):
        return Via.RAW
    if definition.view is View.CONTENT:
        normalized = subject.normalized
        if normalized != subject.raw and definition.test(normalized):
            return Via.NORMALIZED
    return None


def _is_duplicate(subject: Subject) -> Via | None:
    """Another tool in the same listing carries this name, character for character."""
    if subject.names().written[subject.raw] >= 2:
        return Via.RAW
    return None


def _is_lookalike(subject: Subject) -> Via | None:
    """Another tool in the same listing carries a name written differently that reads the same.

    Two names of the listing read alike, and not all of them are this one as written. For a
    name of the listing that is one other spelling; for a string from elsewhere, two names that
    read as it does — the old rule's reach, kept whole by the split."""
    names = subject.names()
    read = names.read[name_key(subject.raw)]
    if read >= 2 and read > names.written[subject.raw]:
        return Via.NORMALIZED
    return None


#: The rule for each signal that compares a name with the rest of its listing.
_NAME_RULES: dict[Signal, Callable[[Subject], Via | None]] = {
    Signal.TOOL_NAME_DUPLICATE: _is_duplicate,
    Signal.TOOL_NAME_LOOKALIKE: _is_lookalike,
}


def fires(signal: Signal, text: str) -> bool:
    """Whether a signal fires on this text on its own, with no listing around it."""
    return check(signal, Subject(text)) is not None


# -- the reference pages ------------------------------------------------------------------

#: The headings every reference page has, in this order. A page
#: is reference knowledge about a pattern, never a statement about a server.
REFERENCE_HEADINGS: tuple[str, ...] = (
    "What the pattern is",
    "Why a model may read it as instruction",
    "How it looks in honest content",
    "Example (invented)",
    "What the tool does not know",
)

#: The line that opens every page's example: the pair is made up, not quoted.
REFERENCE_INVENTED = "Invented for this page; not taken from any server."


def _reference_file(signal: Signal) -> Any:
    # One step at a time: Traversable.joinpath takes a single name before Python 3.11.
    return (
        resources.files("mcp_kymograph")
        .joinpath("data")
        .joinpath("signals")
        .joinpath(f"{signal.value}.md")
    )


def reference(signal: Signal | str) -> str:
    """The reference page of one signal, as Markdown, read from the installed package
    (``data/signals/<id>.md``). A string that is no signal's ID raises :class:`ValueError`."""
    return _reference_file(Signal(signal)).read_bytes().decode("utf-8")


def reference_pages() -> dict[Signal, str]:
    """Every signal's reference page, in the order of :class:`Signal`."""
    return {signal: reference(signal) for signal in Signal}
