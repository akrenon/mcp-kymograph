"""Scenario files: injection rules and observation statements, written down instead of coded.

A scenario file says two things about one assessment, side by side:

* **rules** — what the injection engine changes in the traffic, matched on the MCP level
  (direction, method, field path), never on bytes. Every rule that matches a message acts
  on it, in file order (see :mod:`mcp_kymograph.engine`).
* **observations** — statements about what the *server* delivers that counts as a finding:
  "the description of tool X carries a hidden comment". A statement names signals by their
  ID in the library (:mod:`mcp_kymograph.signals`) and a path; it brings no matcher of its own.
  Statements feed the inspector, which reads the original traffic only, so a statement can
  never report this tool's own injection back as something the server sent.

Both point into messages with the same paths (:mod:`mcp_kymograph.paths`), which are the paths
a recording already prints.

**A file is read whole and refused whole.** Anything the loader does not understand — an
unknown key, an unknown action, a path that does not parse, a value that is not JSON — is
an error naming the file and the place, before any process starts. Nothing is skipped and
nothing is defaulted around, because a scenario that silently loaded less than it says
would make the run's evidence claim more than it holds.

**An empty scenario is a valid scenario.** ``version: 1`` and nothing else loads to no rules
and no statements. Selecting it still opens the engagement gate: the gate keys on the
selection, not on what the file turned out to hold.

**Two front ends, one format.** JSON is read with the standard library and needs nothing.
YAML needs the optional ``yaml`` extra and is read by a loader narrowed to what JSON can
say: no aliases (a few hundred bytes of them can expand to gigabytes), no duplicate keys,
and scalars resolved the YAML 1.2 way, so ``no`` stays the string ``no``, ``1:30`` is not
ninety and a date is not a datetime. A YAML file says exactly what the same file as JSON
would say, or it is refused.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path as FilePath
from typing import Any

from mcp_kymograph.engine import Action, Change, Edited, NoEffect
from mcp_kymograph.events import Direction
from mcp_kymograph.paths import Path, PathSyntaxError, parse, resolve
from mcp_kymograph.signals import Signal

#: The one format version this loader reads. A file must say it, so a later format can be
#: told apart rather than half-read.
FORMAT_VERSION = 1

#: A scenario is written by hand. Anything larger is a mistake, and is refused before it is
#: parsed.
MAX_FILE_BYTES = 1024 * 1024

#: Names end up in events, quarantine notices and terminal lines. A narrow alphabet keeps them
#: printable and greppable everywhere.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

MAX_METHOD_LENGTH = 128

ACTIONS = ("drop", "inject", "replace")
POSITIONS = ("append", "prepend")

_TOP_KEYS = frozenset({"version", "name", "description", "rules", "observations"})
_RULE_KEYS = frozenset(
    {"name", "description", "match", "action", "path", "value", "text", "position"}
)
_STATEMENT_KEYS = frozenset({"name", "description", "match", "path", "signals"})
_RULE_MATCH_KEYS = frozenset({"direction", "method"})


class ScenarioError(ValueError):
    """A scenario file that cannot be used, with the file and the place in it."""


class _YamlRefusal(Exception):
    """Raised from inside the YAML loader, which does not know the file's name."""


# -- what a file turns into ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeclaredRule:
    """One rule from a file. Implements :class:`mcp_kymograph.engine.Rule`.

    Changes the working document in place and reports each change; the engine owns copying,
    ordering and serialising. A message it is meant for but cannot act on is reported as
    :class:`~mcp_kymograph.engine.NoEffect`, never as None, which would mean "not my message".
    """

    name: str
    direction: Direction
    method: str | None
    action: str
    path: Path | None = None
    value: Any = None
    text: str = ""
    position: str = "append"

    @property
    def directions(self) -> frozenset[Direction]:
        return frozenset({self.direction})

    def act(
        self, direction: Direction, document: Any, responded_method: str | None
    ) -> Action | Edited | NoEffect | None:
        if direction is not self.direction or not _method_matches(
            self.method, document, responded_method
        ):
            return None
        if self.action == "drop":
            return Action.DROP

        assert self.path is not None  # noqa: S101 - guaranteed by the loader for these actions
        locations = resolve(document, self.path)
        if not locations:
            return NoEffect(self.action, "path_not_found")

        changes: list[Change] = []
        skipped: list[tuple[str, str]] = []
        for location in locations:
            before = location.value
            if self.action == "inject":
                if not isinstance(before, str):
                    skipped.append((location.path, "not_a_string"))
                    continue
                after = before + self.text if self.position == "append" else self.text + before
                location.set(after)
                changes.append(Change(location.path, before, after))
            else:
                # A fresh copy goes into every message and another into the record: a later
                # step changing the inserted value in place must reach neither the scenario
                # nor what this step is recorded as having done.
                location.set(copy.deepcopy(self.value))
                changes.append(Change(location.path, before, copy.deepcopy(self.value)))
        if not changes:
            return NoEffect(self.action, skipped[0][1], skipped=tuple(skipped))
        return Edited(self.action, tuple(changes), tuple(skipped))


@dataclass(frozen=True, slots=True)
class Statement:
    """One observation statement: at this path, in what the server sends, check these signals."""

    name: str
    method: str | None
    path: Path
    signals: tuple[Signal, ...]

    def applies_to(self, document: Any, responded_method: str | None) -> bool:
        return _method_matches(self.method, document, responded_method)


@dataclass(frozen=True, slots=True)
class Scenario:
    """A loaded file. ``source`` is how it was named; ``digest`` pins what it said.

    ``name`` is the file's own ``name``, or its file name without the suffix when it gives
    none. It goes into the key of every finding, so it is what a later comparison between
    runs matches scenarios on — the source path differs between machines, the name does not.
    """

    source: str
    digest: str
    rules: tuple[DeclaredRule, ...]
    statements: tuple[Statement, ...]
    name: str = ""


def _method_matches(wanted: str | None, document: Any, responded_method: str | None) -> bool:
    """A request or notification matches on its own method, a response on its request's."""
    if wanted is None:
        return True
    own = document.get("method") if isinstance(document, dict) else None
    return (own if isinstance(own, str) else responded_method) == wanted


# -- reading ------------------------------------------------------------------------------


def load(path: FilePath | str) -> Scenario:
    """Read, parse and validate one scenario file, or raise :class:`ScenarioError`."""
    path = FilePath(path)
    source = str(path)
    suffix = path.suffix.lower()
    if suffix not in (".json", ".yaml", ".yml"):
        raise ScenarioError(f"{source}: unknown suffix {suffix!r}; use .yaml, .yml or .json")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ScenarioError(f"{source}: cannot read: {exc.strerror or exc}") from None
    if len(raw) > MAX_FILE_BYTES:
        raise ScenarioError(f"{source}: larger than {MAX_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScenarioError(f"{source}: not UTF-8 at byte {exc.start}") from None

    data = parse_json(text, source=source) if suffix == ".json" else parse_yaml(text, source=source)
    return build(data, source=source, digest=hashlib.sha256(raw).hexdigest(), stem=path.stem)


def parse_json(text: str, *, source: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        return _unique_mapping(items, source)

    def constant(name: str) -> Any:
        raise ScenarioError(f"{source}: {name} is not a JSON value")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except ScenarioError:
        raise
    except json.JSONDecodeError as exc:
        raise ScenarioError(f"{source}: line {exc.lineno} column {exc.colno}: {exc.msg}") from None
    except RecursionError:
        raise ScenarioError(f"{source}: nested too deeply") from None
    except ValueError:
        # json.loads refuses an integer of more than 4300 digits; its message has no value.
        raise ScenarioError(f"{source}: a whole number of too many digits") from None


def parse_yaml(text: str, *, source: str) -> Any:
    try:
        import yaml
    except ImportError:
        raise ScenarioError(
            f"{source}: reading YAML needs the optional dependency — "
            "pip install 'mcp-kymograph[yaml]' — or write the scenario as .json"
        ) from None
    try:
        return yaml.load(text, Loader=_strict_loader(yaml))  # noqa: S506 - narrowed SafeLoader
    except _YamlRefusal as refusal:
        raise ScenarioError(f"{source}: {refusal}") from None
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        where = f"line {mark.line + 1} column {mark.column + 1}: " if mark else ""
        raise ScenarioError(f"{source}: {where}{exc.problem or exc}") from None
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{source}: {exc}") from None
    except RecursionError:
        raise ScenarioError(f"{source}: nested too deeply") from None
    except (ValueError, KeyError, AttributeError, IndexError, TypeError):
        # Explicit tags are refused in the loader, and whole numbers are checked there. This is
        # the second line: a constructor inherited from SafeLoader that still fails on text it
        # cannot read. Python's message may carry the text; none is used.
        raise ScenarioError(f"{source}: a value that cannot be read") from None


_LOADER: Any = None
_DECIMAL = re.compile(r"[-+]?[0-9]+")
_MAX_DIGITS = 4300  # Python's own limit for int() on decimal text, which other bases escape


def _strict_loader(yaml: Any) -> Any:
    """A SafeLoader narrowed to JSON's data model. Built once, on first use."""
    global _LOADER
    if _LOADER is not None:
        return _LOADER

    class StrictLoader(yaml.SafeLoader):
        def scan_directive(self) -> Any:
            # A `%TAG` directive rebinds a handle, so `!!int` could name another tag. No file of
            # this tool needs one: refuse it as it is read, before any of its text is scanned.
            if self.prefix(4) == "%TAG" and self.peek(4) in "\0 \t\r\n\x85  ":
                raise _YamlRefusal(f"line {self.get_mark().line + 1}: YAML tags are not allowed")
            return super().scan_directive()

        def scan_tag(self) -> Any:
            # Every explicit tag, however spelled (`!!x`, `!x`, `!<x>`, a `%TAG` handle), is a
            # token here. The one exception is `!!int`, which the whole-number check below reads.
            token = super().scan_tag()
            if token.value != ("!!", "int"):
                raise _YamlRefusal(f"line {token.start_mark.line + 1}: YAML tags are not allowed")
            return token

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                event = self.peek_event()
                raise _YamlRefusal(
                    f"line {event.start_mark.line + 1}: YAML aliases are not allowed in a scenario"
                )
            return super().compose_node(parent, index)

        def construct_mapping(self, node: Any, deep: bool = False) -> Any:
            seen: set[Any] = set()
            for key_node, _value in node.value:
                key = self.construct_object(key_node, deep=deep)
                line = key_node.start_mark.line + 1
                if not isinstance(key, str):
                    raise _YamlRefusal(f"line {line}: key {key!r} is not a string")
                if key in seen:
                    raise _YamlRefusal(f"line {line}: duplicate key {key!r}")
                seen.add(key)
            return super().construct_mapping(node, deep=deep)

        def construct_yaml_int(self, node: Any) -> int:
            # The core schema of YAML 1.2: decimal digits and a sign, nothing else. 1.1 reads a
            # leading 0 as octal, and 0x, 0b and 1:2:3 as numbers that int() does not limit.
            text = self.construct_scalar(node)
            line = node.start_mark.line + 1
            if not _DECIMAL.fullmatch(text):
                raise _YamlRefusal(f"line {line}: not a whole number in decimal digits")
            if len(text.lstrip("+-")) > _MAX_DIGITS:
                raise _YamlRefusal(f"line {line}: a whole number of too many digits")
            return int(text)

    StrictLoader.add_constructor("tag:yaml.org,2002:int", StrictLoader.construct_yaml_int)
    # The YAML 1.2 core schema instead of 1.1's: only these spellings are not strings.
    StrictLoader.yaml_implicit_resolvers = {}
    resolvers = (
        ("tag:yaml.org,2002:null", r"^(?:~|null|Null|NULL|)$", ["~", "n", "N", ""]),
        ("tag:yaml.org,2002:bool", r"^(?:true|True|TRUE|false|False|FALSE)$", list("tTfF")),
        ("tag:yaml.org,2002:int", r"^[-+]?[0-9]+$", list("-+0123456789")),
        (
            "tag:yaml.org,2002:float",
            r"^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?$",
            list("-+.0123456789"),
        ),
    )
    for tag, pattern, first in resolvers:
        StrictLoader.add_implicit_resolver(tag, re.compile(pattern), first)
    _LOADER = StrictLoader
    return _LOADER


def _unique_mapping(items: list[tuple[str, Any]], source: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ScenarioError(f"{source}: duplicate key {key!r}")
        result[key] = value
    return result


# -- validating ---------------------------------------------------------------------------


def build(data: Any, *, source: str, digest: str = "", stem: str = "") -> Scenario:
    """Turn parsed data into a scenario, or raise naming the first thing that is wrong."""
    try:
        return _build(data, source, digest, stem)
    except _Invalid as invalid:
        where = f"{invalid.where}: " if invalid.where else ""
        raise ScenarioError(f"{source}: {where}{invalid.message}") from None


class _Invalid(Exception):
    def __init__(self, where: str, message: str) -> None:
        super().__init__(message)
        self.where = where
        self.message = message


def _build(data: Any, source: str, digest: str, stem: str) -> Scenario:
    _mapping(data, "", "the scenario must be a mapping")
    _only(data, _TOP_KEYS, "")
    version = data.get("version")
    if "version" not in data:
        raise _Invalid("version", f"missing; this loader reads version: {FORMAT_VERSION}")
    if type(version) is not int or version != FORMAT_VERSION:
        raise _Invalid("version", f"unsupported {version!r}; this loader reads {FORMAT_VERSION}")
    for key in ("name", "description"):
        if key in data and not isinstance(data[key], str):
            raise _Invalid(key, "expected a string")

    names: set[str] = set()
    rules = tuple(
        _rule(item, f"rules[{index}]", names) for index, item in enumerate(_section(data, "rules"))
    )
    statements = tuple(
        _statement(item, f"observations[{index}]", names)
        for index, item in enumerate(_section(data, "observations"))
    )
    return Scenario(
        source=source,
        digest=digest,
        rules=rules,
        statements=statements,
        name=data.get("name") or stem,
    )


def _section(data: dict, key: str) -> Sequence[Any]:
    # A section whose every entry is commented out reads as null. That is an empty section,
    # which is exactly what the author left — not a malformed one.
    value = data.get(key)
    if value is None:
        return ()
    if not isinstance(value, list):
        raise _Invalid(key, "expected a list")
    return value


def _rule(item: Any, where: str, names: set[str]) -> DeclaredRule:
    _mapping(item, where, "expected a mapping")
    _only(item, _RULE_KEYS, where)
    name = _name(item, where, names)

    match = _required(item, "match", where)
    _mapping(match, f"{where}.match", "expected a mapping")
    _only(match, _RULE_MATCH_KEYS, f"{where}.match")
    direction = _direction(_required(match, "direction", f"{where}.match"), f"{where}.match")
    method = _method(match, f"{where}.match")

    action = item.get("action")
    if action not in ACTIONS:
        raise _Invalid(
            f"{where}.action", f"unknown action {action!r}; expected one of {', '.join(ACTIONS)}"
        )

    allowed = {"drop": set(), "inject": {"path", "text", "position"}, "replace": {"path", "value"}}
    for key in ("path", "value", "text", "position"):
        if key in item and key not in allowed[action]:
            raise _Invalid(f"{where}.{key}", f"not allowed for action {action!r}")

    if action == "drop":
        return DeclaredRule(name=name, direction=direction, method=method, action=action)

    path = _path(_required(item, "path", where), f"{where}.path")
    if action == "replace":
        # Present is what counts, not non-null: setting a field to null is a replacement.
        if "value" not in item:
            raise _Invalid(f"{where}.value", "missing")
        value = item["value"]
        _json_value(value, f"{where}.value")
        return DeclaredRule(name, direction, method, action, path=path, value=value)

    text = _required(item, "text", where)
    if not isinstance(text, str):
        raise _Invalid(f"{where}.text", "expected a string")
    position = item.get("position", "append")
    if position not in POSITIONS:
        raise _Invalid(
            f"{where}.position",
            f"unknown position {position!r}; expected one of {', '.join(POSITIONS)}",
        )
    return DeclaredRule(name, direction, method, action, path=path, text=text, position=position)


def _statement(item: Any, where: str, names: set[str]) -> Statement:
    _mapping(item, where, "expected a mapping")
    _only(item, _STATEMENT_KEYS, where)
    name = _name(item, where, names)

    method = None
    if "match" in item:
        match = item["match"]
        _mapping(match, f"{where}.match", "expected a mapping")
        _only(match, _RULE_MATCH_KEYS, f"{where}.match")
        if "direction" in match:
            direction = _direction(match["direction"], f"{where}.match")
            if direction is not Direction.SERVER_TO_CLIENT:
                raise _Invalid(
                    f"{where}.match.direction",
                    "an observation is about what the server delivers; "
                    "only server_to_client is possible",
                )
        method = _method(match, f"{where}.match")

    path = _path(_required(item, "path", where), f"{where}.path")
    names = _required(item, "signals", where)
    if not isinstance(names, list):
        raise _Invalid(f"{where}.signals", "expected a list")
    if not names:
        raise _Invalid(f"{where}.signals", "empty; name at least one signal")
    known = {signal.value: signal for signal in Signal if signal is not Signal.LONE_SURROGATE}
    signals: list[Signal] = []
    for index, signal in enumerate(names):
        if signal == Signal.LONE_SURROGATE.value:
            raise _Invalid(
                f"{where}.signals[{index}]",
                f"{signal!r} cannot be asked for: only the inspector sets it, when it replaced "
                "a lone surrogate in the announced server name; it is no property of a text "
                "at a path",
            )
        if not isinstance(signal, str) or signal not in known:
            raise _Invalid(
                f"{where}.signals[{index}]",
                f"unknown signal {signal!r}; expected one of {', '.join(sorted(known))}",
            )
        if known[signal] in signals:
            raise _Invalid(f"{where}.signals[{index}]", f"{signal!r} is listed twice")
        signals.append(known[signal])
    return Statement(name=name, method=method, path=path, signals=tuple(signals))


# -- small checks -------------------------------------------------------------------------


def _mapping(value: Any, where: str, message: str) -> None:
    if not isinstance(value, dict):
        raise _Invalid(where, message)


def _only(mapping: dict, allowed: frozenset[str], where: str) -> None:
    for key in mapping:
        if key not in allowed:
            raise _Invalid(
                where, f"unknown key {key!r}; expected one of {', '.join(sorted(allowed))}"
            )


def _required(mapping: dict, key: str, where: str) -> Any:
    if key not in mapping or mapping[key] is None:
        raise _Invalid(f"{where}.{key}", "missing")
    return mapping[key]


def _name(item: dict, where: str, names: set[str]) -> str:
    name = _required(item, "name", where)
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise _Invalid(
            f"{where}.name",
            f"{name!r} is not a name: 1-64 characters, letters, digits, '.', '_', '-'",
        )
    if name in names:
        raise _Invalid(f"{where}.name", f"{name!r} is already used in this scenario")
    names.add(name)
    return name


def _direction(value: Any, where: str) -> Direction:
    try:
        return Direction(value)
    except ValueError:
        expected = ", ".join(direction.value for direction in Direction)
        raise _Invalid(
            f"{where}.direction", f"unknown direction {value!r}; expected one of {expected}"
        ) from None


def _method(match: dict, where: str) -> str | None:
    if "method" not in match:
        return None
    method = match["method"]
    if not isinstance(method, str):
        raise _Invalid(f"{where}.method", "expected a string")
    if not method:
        raise _Invalid(f"{where}.method", "empty; leave the key out to match any method")
    if len(method) > MAX_METHOD_LENGTH:
        raise _Invalid(f"{where}.method", f"longer than {MAX_METHOD_LENGTH} characters")
    return method


def _path(value: Any, where: str) -> Path:
    if not isinstance(value, str):
        raise _Invalid(where, "expected a string")
    try:
        return parse(value)
    except PathSyntaxError as exc:
        raise _Invalid(where, str(exc)) from None


def _json_value(value: Any, where: str) -> None:
    """Only what JSON can carry. Anything else would fail at the first message, not now."""
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _Invalid(where, f"{value!r} is not a JSON number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_value(item, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _Invalid(where, f"key {key!r} is not a string")
            _json_value(item, f"{where}.{key}")
        return
    raise _Invalid(where, f"a {type(value).__name__} is not a JSON value")
