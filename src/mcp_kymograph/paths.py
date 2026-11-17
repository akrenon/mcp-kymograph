"""Field paths: where in an MCP message something sits.

**One syntax for everything that points into a message.** The recording already writes paths
— ``observation.path``, a payload's ``redactions`` — as ``result.tools[0].description``. A
scenario file uses the same form, so a path read off a recording can be pasted into a rule or
a statement unchanged, and a path a rule changed reads exactly like one the inspector saw.
JSON Pointer would have been a second dialect for the same thing.

The grammar, and nothing else::

    path     := key ( "." key | "[" selector "]" )*
    key      := [A-Za-z_$] [A-Za-z0-9_$-]*
    selector := index | "*" | key "=" string
    index    := "0" | [1-9][0-9]*
    string   := a JSON string literal, "double-quoted"

``[*]`` is every element of a list; ``[name="get_weather"]`` is every element that is an
object whose ``name`` is exactly that string. Both resolve to concrete indices, so what a
recording shows is always a position, never a pattern.

A key outside that alphabet cannot be addressed. That is a refusal, not an omission: a key
with a dot or a space in it would need a quoting rule, and a quoting rule is one more thing a
scenario author can get wrong without noticing. Should a real server need one, it is added
then, with its own test.

**Every resolved place also carries a locator** — the same place, named instead of
numbered. A position says where something sat in *this* message; a locator says *what* it
was, so that the same thing in the next run, behind an inserted tool, reads the same. One
rule, applied to every list step whatever the author wrote (``[3]``, ``[*]`` or a selector):
the step becomes the element's own identity, ``[name="get_weather"]``, or ``[]`` when it has
none. Key steps stay as they are.

**Which member is an element's identity is the protocol's answer, not a guess.** The element
type follows from where its list sits in the message — ``result.tools`` holds tools,
``result.resources`` resources — and :data:`IDENTITY_FIELDS` says, per type, the member MCP
uses to tell two of them apart: ``name`` for a tool, ``uri`` for a resource, whose ``name`` is
only a display name and may repeat. A list the table does not know has no protocol identity,
and its steps are ``[]``. The walk does not branch on the type; it looks the field up.

**Resolution never raises on the document.** A path that is not there resolves to nothing;
whether nothing is an error is the caller's decision — for a rule it is a logged step with no
effect, for a statement it is simply nothing to look at. Only the *path itself* can be wrong,
and that is reported when the file is loaded, with the position.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

#: A path longer than this is refused. Nothing in MCP nests anywhere near it; a path that long
#: is a mistake, and resolution cost grows with it.
MAX_PATH_LENGTH = 512

#: The identifying member per element type, from the MCP schema. A type is named by where its
#: list sits, as a path with every list step written ``[]`` — so a ``tools`` list nested in
#: some tool's structured output is not the tools of a ``tools/list`` answer, and is not
#: identified as one.
#:
#: * Tool, Prompt, PromptArgument — ``name``: unique within the server or the prompt.
#: * Resource — ``uri``. Its ``name`` is a display name and may repeat; two resources that
#:   share it are still two resources.
#: * ResourceTemplate — ``uriTemplate``.
#: * ResourceContents in a ``resources/read`` answer — ``uri``.
#:
#: Content blocks (``result.content``), prompt messages and every list not named here have
#: no protocol identity: their locator step is ``[]``.
IDENTITY_FIELDS: dict[str, str] = {
    "result.tools": "name",
    "result.prompts": "name",
    "result.prompts[].arguments": "name",
    "result.resources": "uri",
    "result.resourceTemplates": "uriTemplate",
    "result.contents": "uri",
}

_KEY = re.compile(r"[A-Za-z_$][A-Za-z0-9_$-]*")
_INDEX = re.compile(r"0|[1-9][0-9]*")
_LEADING_ZERO = re.compile(r"0[0-9]")


class PathSyntaxError(ValueError):
    """A path that does not parse. Says where, because a scenario author has to find it."""


@dataclass(frozen=True, slots=True)
class Key:
    name: str


@dataclass(frozen=True, slots=True)
class Index:
    position: int


@dataclass(frozen=True, slots=True)
class Every:
    pass


@dataclass(frozen=True, slots=True)
class Where:
    key: str
    value: str


Step = Key | Index | Every | Where


@dataclass(frozen=True, slots=True)
class Path:
    """A parsed path. ``text`` is what the author wrote, kept for messages and the record."""

    text: str
    steps: tuple[Step, ...]


@dataclass(frozen=True, slots=True)
class Location:
    """One place a path resolved to: its concrete spelling, and a handle to change it.

    ``path`` is the position (``result.tools[3].description``); ``locator`` is the same place
    by identity (``result.tools[name="search"].description``). Two elements that carry the
    same identity share a locator: two tools with one name are, by identity, one tool — the
    ``tool_name_duplicate`` signal exists to say so. Two resources with one display name and
    two URIs are two resources, because a resource's identity is its URI.
    """

    path: str
    container: dict | list
    slot: str | int
    locator: str = ""

    @property
    def value(self) -> Any:
        return self.container[self.slot]  # type: ignore[index]

    def set(self, value: Any) -> None:
        self.container[self.slot] = value  # type: ignore[index]


def parse(text: str) -> Path:
    """Parse one path or raise :class:`PathSyntaxError` naming the position."""
    if not isinstance(text, str) or not text:
        raise PathSyntaxError("path is empty")
    if len(text) > MAX_PATH_LENGTH:
        raise PathSyntaxError(f"path is longer than {MAX_PATH_LENGTH} characters")

    steps: list[Step] = []
    match = _KEY.match(text, 0)
    if match is None:
        if text.startswith("["):
            raise PathSyntaxError("path must start with a key, not with a [selector]")
        raise PathSyntaxError(f"expected a key at position 0 in {text!r}")
    steps.append(Key(match.group()))
    position = match.end()

    while position < len(text):
        character = text[position]
        if character == ".":
            match = _KEY.match(text, position + 1)
            if match is None:
                raise PathSyntaxError(f"expected a key at position {position + 1} in {text!r}")
            steps.append(Key(match.group()))
            position = match.end()
        elif character == "[":
            step, position = _selector(text, position + 1)
            steps.append(step)
        else:
            raise PathSyntaxError(
                f"unexpected {character!r} at position {position} in {text!r}; "
                "a key may hold only letters, digits, '_', '$' and '-'"
            )
    return Path(text=text, steps=tuple(steps))


def _selector(text: str, start: int) -> tuple[Step, int]:
    """One ``[...]`` body starting at ``start``; returns the step and the position after ``]``."""
    if start >= len(text):
        raise PathSyntaxError(f"unclosed [ at position {start - 1} in {text!r}")
    if text[start] == "*":
        return Every(), _close(text, start + 1)
    if _LEADING_ZERO.match(text, start):
        raise PathSyntaxError(f"index with a leading zero at position {start} in {text!r}")
    match = _INDEX.match(text, start)
    if match is not None:
        return Index(int(match.group())), _close(text, match.end())
    match = _KEY.match(text, start)
    if match is None:
        raise PathSyntaxError(
            f"expected an index, '*' or key=\"value\" at position {start} in {text!r}"
        )
    key = match.group()
    position = match.end()
    if position >= len(text) or text[position] != "=":
        raise PathSyntaxError(f"expected '=' at position {position} in {text!r}")
    position += 1
    if position >= len(text) or text[position] != '"':
        raise PathSyntaxError(
            f'a selector value must be quoted, "like this", at position {position} in {text!r}'
        )
    value, position = _string(text, position)
    return Where(key, value), _close(text, position)


def _string(text: str, start: int) -> tuple[str, int]:
    """A JSON string literal starting at the opening quote."""
    position = start + 1
    while position < len(text):
        if text[position] == "\\":
            position += 2
            continue
        if text[position] == '"':
            try:
                value = json.loads(text[start : position + 1])
            except ValueError as exc:
                raise PathSyntaxError(
                    f"invalid string at position {start} in {text!r}: {exc}"
                ) from None
            return value, position + 1
        position += 1
    raise PathSyntaxError(f"unclosed string at position {start} in {text!r}")


def _close(text: str, position: int) -> int:
    if position >= len(text):
        raise PathSyntaxError(f"unclosed [ in {text!r}")
    if text[position] != "]":
        raise PathSyntaxError(f"expected ']' at position {position} in {text!r}")
    return position + 1


def resolve(document: Any, path: Path) -> list[Location]:
    """Every place in ``document`` this path names, in document order. Never raises."""
    return list(_walk(document, path.steps, _Trail("", "", ""), None, None))


@dataclass(frozen=True, slots=True)
class _Trail:
    """Three spellings of the way down, built together: the position (``spelled``), the
    locator (``located``) and the element-type shape (``shape``, every list step ``[]``)."""

    spelled: str
    located: str
    shape: str

    def key(self, name: str) -> _Trail:
        if not self.spelled:
            return _Trail(name, name, name)
        return _Trail(f"{self.spelled}.{name}", f"{self.located}.{name}", f"{self.shape}.{name}")

    def element(self, position: int, item: Any) -> _Trail:
        field = IDENTITY_FIELDS.get(self.shape)
        return _Trail(
            f"{self.spelled}[{position}]", self.located + identity(item, field), self.shape + "[]"
        )


def _walk(
    node: Any, steps: tuple[Step, ...], trail: _Trail, container: Any, slot: Any
) -> Iterator[Location]:
    if not steps:
        if container is not None:
            yield Location(trail.spelled, container, slot, trail.located)
        return
    step, rest = steps[0], steps[1:]
    if isinstance(step, Key):
        if isinstance(node, dict) and step.name in node:
            yield from _walk(node[step.name], rest, trail.key(step.name), node, step.name)
        return
    if not isinstance(node, list):
        return
    if isinstance(step, Index):
        if step.position < len(node):
            item = node[step.position]
            yield from _walk(item, rest, trail.element(step.position, item), node, step.position)
        return
    for position, item in enumerate(node):
        if isinstance(step, Where) and not (
            isinstance(item, dict) and _same_string(item.get(step.key), step.value)
        ):
            continue
        yield from _walk(item, rest, trail.element(position, item), node, position)


def identity(item: Any, field: str | None) -> str:
    """The locator step for one list element: its identity as a selector, or ``[]``.

    ``field`` is the identifying member for the element's type, from :data:`IDENTITY_FIELDS`,
    or None for a list the protocol gives no identity. An element that lacks the member, or
    carries it as something other than a string, has no identity either.

    The value is written as a JSON string with every non-ASCII character escaped, so a
    lookalike letter or an invisible character in a name is visible in the locator rather
    than hidden in it, and the step is a selector :func:`parse` reads back unchanged.
    """
    if field is not None and isinstance(item, dict):
        value = item.get(field)
        if isinstance(value, str):
            return f"[{field}={json.dumps(value)}]"
    return "[]"


def _same_string(value: Any, wanted: str) -> bool:
    return isinstance(value, str) and value == wanted
