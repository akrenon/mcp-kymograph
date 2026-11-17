"""Script files: what the driver says to a server, written down instead of coded.

A script file is a short, fixed conversation. After the handshake it lists, and it may call
tools::

    version: 1
    name: read-the-notes
    steps:
      - initialize
      - list: tools/list
      - call:
          tool: read_note
          arguments: {path: "{fixture_dir}/note.txt"}
          check: result.content[*].text
          timeout: 20

**A file says what it does; nothing is added.** ``initialize`` is the first step and the only
one of its kind, and a file without it, or with it elsewhere, is refused rather than mended.
A ``call`` is only meaningful after a ``tools/list`` that can have delivered its tool, so a
file with a call and no earlier ``tools/list`` is refused as well. The driver decides at run
time whether the server really delivered it (:mod:`mcp_kymograph.driver`).

**Bounded.** At most :data:`MAX_STEPS` steps and :data:`MAX_CALLS` of them calls, each with a
time between the driver's own least (:data:`~mcp_kymograph.driver.MIN_STEP_TIMEOUT`) and
:data:`MAX_CALL_TIMEOUT`. A script is written by hand; a long one is a mistake, or a tool in
the making, and neither belongs here.

**Placeholders** stand in string values of ``arguments`` for what only the operator of this
run knows: ``{fixture_url}``, ``{fixture_dir}``, ``{repo_path}``, ``{db_path}``, ``{canary}``
(:data:`PLACEHOLDERS`, a fixed list). Their values come from ``--script-var NAME=VALUE``.
Replacement is textual and in strings only — no evaluation, no nesting, nothing is looked up
in the environment — and ``{{`` and ``}}`` stand for a brace of their own. An unknown
placeholder, a placeholder without a value, a value for a name the list does not have and a
stray brace are refused before anything starts.

**A file is read whole and refused whole**, as a scenario is (:mod:`mcp_kymograph.scenario`,
whose reading of JSON and of YAML on JSON's data model this uses as it is): every refusal
names the file and the place in it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path as FilePath
from typing import Any

from mcp_kymograph import events
from mcp_kymograph.driver import (
    DISCOVERY,
    MIN_STEP_TIMEOUT,
    CallStep,
    Script,
    Step,
)
from mcp_kymograph.paths import PathSyntaxError, parse
from mcp_kymograph.scenario import (
    _NAME,
    FORMAT_VERSION,
    MAX_FILE_BYTES,
    ScenarioError,
    _Invalid,
    _json_value,
    _mapping,
    _only,
    _required,
    parse_json,
    parse_yaml,
)

#: At most this many steps in a file, the handshake included.
MAX_STEPS = 32
#: At most this many of them calls.
MAX_CALLS = 8
#: The longest a single call may be given to answer, in seconds.
MAX_CALL_TIMEOUT = 120.0
#: The longest tool name a call may carry; the recording caps it at a method name's length.
MAX_TOOL_LENGTH = events.MAX_METHOD_LENGTH

#: The suffixes by which a name is taken for a file.
SUFFIXES = (".json", ".yaml", ".yml")

#: What a placeholder may stand for. A fixed list: a placeholder is not a way to read the
#: environment, and a typo in a name is refused instead of left in an argument.
PLACEHOLDERS = ("fixture_url", "fixture_dir", "repo_path", "db_path", "canary")

#: The lists a ``list`` step may ask for, with the capability each needs (the same table the
#: built-in script has).
LISTS = {
    "tools/list": "tools",
    "resources/list": "resources",
    "resources/templates/list": "resources",
    "prompts/list": "prompts",
}

_TOP_KEYS = frozenset({"version", "name", "steps"})
_CALL_KEYS = frozenset({"tool", "arguments", "check", "timeout"})
_STEP_KEYS = frozenset({"list", "call"})

_BRACES = re.compile(r"\{\{|\}\}|\{([^{}]*)\}|[{}]")


class ScriptError(ValueError):
    """A script file that cannot be used, with the file and the place in it.

    ``where`` is the place alone (``steps[1].call.tool``), without the file or what is wrong
    there; empty where the error has none (the file, a variable, the top of the document)."""

    def __init__(self, message: str, where: str = "") -> None:
        super().__init__(message)
        self.where = where


def is_file_name(text: str) -> bool:
    """Whether a ``--script`` argument names a file rather than a built-in script: by its
    suffix, which also says how the file is read — not by whether a file of that name exists."""
    return FilePath(text).suffix.lower() in SUFFIXES


def parse_variables(items: list[str] | None) -> dict[str, str]:
    """``NAME=VALUE`` as given on the command line, or :class:`ScriptError`. A name the list
    of placeholders does not have is refused here, and so is one given twice."""
    variables: dict[str, str] = {}
    for item in items or ():
        name, separator, value = item.partition("=")
        if not separator:
            raise ScriptError(f"--script-var {item!r}: expected NAME=VALUE")
        if name not in PLACEHOLDERS:
            raise ScriptError(
                f"--script-var {name!r}: unknown name; expected one of {', '.join(PLACEHOLDERS)}"
            )
        if name in variables:
            raise ScriptError(f"--script-var {name!r}: given twice")
        variables[name] = value
    return variables


def load(path: FilePath | str, variables: Mapping[str, str] | None = None) -> Script:
    """Read, validate and fill in one script file, or raise :class:`ScriptError`."""
    path = FilePath(path)
    source = str(path)
    values = dict(variables or {})
    suffix = path.suffix.lower()
    if suffix not in SUFFIXES:
        raise ScriptError(f"{source}: unknown suffix {suffix!r}; use .yaml, .yml or .json")
    for name in values:
        if name not in PLACEHOLDERS:
            raise ScriptError(f"--script-var {name!r}: unknown name")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ScriptError(f"{source}: cannot read: {exc.strerror or exc}") from None
    if len(raw) > MAX_FILE_BYTES:
        raise ScriptError(f"{source}: larger than {MAX_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScriptError(f"{source}: not UTF-8 at byte {exc.start}") from None
    try:
        data = (
            parse_json(text, source=source)
            if suffix == ".json"
            else parse_yaml(text, source=source)
        )
    except ScenarioError as refusal:
        raise ScriptError(str(refusal)) from None
    return build(data, source=source, digest=hashlib.sha256(raw).hexdigest(), variables=values)


def build(
    data: Any, *, source: str, digest: str | None = None, variables: Mapping[str, str] | None = None
) -> Script:
    """Turn parsed data into a script, or raise naming the first thing that is wrong."""
    values = dict(variables or {})
    try:
        return _build(data, source, digest, values)
    except _Invalid as invalid:
        where = f"{invalid.where}: " if invalid.where else ""
        raise ScriptError(f"{source}: {where}{invalid.message}", invalid.where) from None


def _build(data: Any, source: str, digest: str | None, values: dict[str, str]) -> Script:
    _mapping(data, "", "the script must be a mapping")
    _only(data, _TOP_KEYS, "")
    if "version" not in data:
        raise _Invalid("version", f"missing; this loader reads version: {FORMAT_VERSION}")
    version = data["version"]
    if type(version) is not int or version != FORMAT_VERSION:
        raise _Invalid("version", f"unsupported {version!r}; this loader reads {FORMAT_VERSION}")
    name = data.get("name")
    if name is None:
        raise _Invalid("name", "missing")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise _Invalid(
            "name", f"{name!r} is not a name: 1-64 characters, letters, digits, '.', '_', '-'"
        )
    items = data.get("steps")
    if items is None:
        raise _Invalid("steps", "missing")
    if not isinstance(items, list):
        raise _Invalid("steps", "expected a list")
    if len(items) > MAX_STEPS:
        raise _Invalid("steps", f"{len(items)} steps; at most {MAX_STEPS}")
    if not items or items[0] != "initialize":
        raise _Invalid("steps[0]", "the first step must be: initialize")

    steps: list[Step | CallStep] = []
    listed_tools = False
    calls = 0
    for index, item in enumerate(items[1:], start=1):
        where = f"steps[{index}]"
        if item == "initialize":
            raise _Invalid(where, "initialize is the first step and comes once")
        if not isinstance(item, dict):
            raise _Invalid(where, "expected a mapping with list or call (or the first step)")
        _only(item, _STEP_KEYS, where)
        if len(item) != 1:
            raise _Invalid(where, "a step holds exactly one of list, call")
        if "list" in item:
            method = item["list"]
            if method not in LISTS:
                raise _Invalid(
                    f"{where}.list",
                    f"unknown list {method!r}; expected one of {', '.join(LISTS)}",
                )
            listed_tools = listed_tools or method == "tools/list"
            steps.append(Step(method, requires=LISTS[method], paginate=True))
            continue
        calls += 1
        if calls > MAX_CALLS:
            raise _Invalid(where, f"more than {MAX_CALLS} calls")
        if not listed_tools:
            raise _Invalid(
                where, "a call needs a tools/list step before it: a tool is not called unseen"
            )
        steps.append(_call(item["call"], f"{where}.call", values))
    return Script(
        name=name,
        protocol_version=DISCOVERY.protocol_version,
        client_info=DISCOVERY.client_info,
        capabilities=DISCOVERY.capabilities,
        steps=tuple(steps),
        digest=digest,
        variables=dict(values),
    )


def _call(item: Any, where: str, values: dict[str, str]) -> CallStep:
    _mapping(item, where, "expected a mapping")
    _only(item, _CALL_KEYS, where)
    tool = _required(item, "tool", where)
    if not isinstance(tool, str) or not tool or len(tool) > MAX_TOOL_LENGTH:
        raise _Invalid(f"{where}.tool", f"expected a tool name of 1-{MAX_TOOL_LENGTH} characters")
    arguments = item.get("arguments")
    if arguments is None:
        arguments = {}
    _mapping(arguments, f"{where}.arguments", "expected a mapping")
    _json_value(arguments, f"{where}.arguments")
    if events.deeper_than(arguments, events.MAX_DOCUMENT_DEPTH):
        raise _Invalid(f"{where}.arguments", "nested too deeply")
    arguments = _filled(arguments, f"{where}.arguments", values)

    check = item.get("check")
    if check is not None:
        if not isinstance(check, str):
            raise _Invalid(f"{where}.check", "expected a string")
        try:
            parsed = parse(check)
        except PathSyntaxError as exc:
            raise _Invalid(f"{where}.check", str(exc)) from None
        if parsed.steps[0].name != "result":
            raise _Invalid(f"{where}.check", "a path into the answer starts with result")

    timeout = item.get("timeout")
    if timeout is not None:
        # The range alone: it refuses nan and inf as well, and compares an integer of any size
        # exactly, where ``math.isfinite`` would overflow on one beyond a float.
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not MIN_STEP_TIMEOUT <= timeout <= MAX_CALL_TIMEOUT
        ):
            raise _Invalid(
                f"{where}.timeout",
                f"expected seconds from {MIN_STEP_TIMEOUT:g} to {MAX_CALL_TIMEOUT:g}",
            )
        timeout = float(timeout)
    return CallStep(tool=tool, arguments=arguments, check=check, timeout=timeout)


def _filled(value: Any, where: str, values: dict[str, str]) -> Any:
    """``value`` with the placeholders in its strings replaced. Keys are not touched."""
    if isinstance(value, str):
        return _fill(value, where, values)
    if isinstance(value, list):
        return [_filled(item, f"{where}[{index}]", values) for index, item in enumerate(value)]
    if isinstance(value, dict):
        return {key: _filled(item, f"{where}.{key}", values) for key, item in value.items()}
    return value


def _fill(text: str, where: str, values: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        found = match.group(0)
        if found == "{{":
            return "{"
        if found == "}}":
            return "}"
        name = match.group(1)
        if name is None:
            raise _Invalid(where, f"a stray {found!r}; write {found * 2!r} for the character")
        if name not in PLACEHOLDERS:
            raise _Invalid(
                where, f"unknown placeholder {{{name}}}; expected one of {', '.join(PLACEHOLDERS)}"
            )
        if name not in values:
            raise _Invalid(
                where, f"placeholder {{{name}}} has no value; give --script-var {name}=…"
            )
        return values[name]

    # One pass over the original text: a value that itself holds a brace is not read again.
    return _BRACES.sub(replace, text)
