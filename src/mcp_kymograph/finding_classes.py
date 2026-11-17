"""Finding classes: the stable groups every signal and every rule belongs to.

A class has an ID (``AKR-NN``, two digits, stable, never reused), an English title and one
sentence of description. Each signal ID and each rule ID belongs to exactly one class. A class is
no severity and has no rank: the list is ordered by ID only so that it reads the same twice.

The class is derived when a finding is rendered, from the signal or rule ID; it is never stored,
so a finding's key does not change when this table does (docs/finding-classes.md).

The second half of the module reads and checks the open mapping file from classes to entries of
outside frameworks (``data/finding-classes-mapping.yaml``). The file holds IDs and numbers
only, never a title or a text from a source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

from mcp_kymograph.rules import ToolPoisoning
from mcp_kymograph.scenario import ScenarioError, parse_yaml
from mcp_kymograph.signals import Signal


@dataclass(frozen=True, slots=True)
class FindingClass:
    id: str
    title: str
    description: str

    def label(self) -> str:
        """The class as a finding shows it: ID and title."""
        return f"{self.id} {self.title}"

    def to_dict(self) -> dict[str, str]:
        return {"id": self.id, "title": self.title, "description": self.description}


#: The classes. An ID is never reused: a class that goes away leaves its number unused.
CLASSES: tuple[FindingClass, ...] = (
    FindingClass(
        "AKR-01",
        "Concealed content",
        "Text a person reading the tool metadata would not see, or could not read as written.",
    ),
    FindingClass(
        "AKR-02",
        "Directive to the model",
        "Wording in tool metadata that addresses or instructs the model rather than describing "
        "the tool.",
    ),
    FindingClass(
        "AKR-03",
        "Imitated prompt structure",
        "Markers or lines in tool metadata that imitate the structure of a chat prompt.",
    ),
    FindingClass(
        "AKR-04",
        "Embedded external reference",
        "A link in tool metadata that points the reader, or the model, to somewhere else.",
    ),
    FindingClass(
        "AKR-05",
        "Ambiguous or malformed name",
        "A tool name that is the same as another or reads like another, or a tool or server name "
        "that is not well-formed text.",
    ),
)

#: Signal ID -> class ID. One entry per signal, none left to a default (a test holds it).
SIGNAL_CLASSES: dict[Signal, str] = {
    Signal.INVISIBLE_CHARACTERS: "AKR-01",
    Signal.CHAT_TEMPLATE_MARKER: "AKR-03",
    Signal.INSTRUCTION_OVERRIDE: "AKR-02",
    Signal.CONCEALMENT_DIRECTIVE: "AKR-02",
    Signal.OUTPUT_DIRECTIVE: "AKR-02",
    Signal.MODEL_ADDRESSED: "AKR-02",
    Signal.HIDDEN_COMMENT: "AKR-01",
    Signal.ROLE_LINE: "AKR-03",
    Signal.WHITESPACE_PADDING: "AKR-01",
    Signal.IMPERATIVE: "AKR-02",
    Signal.SECOND_PERSON: "AKR-02",
    Signal.EMBEDDED_URL: "AKR-04",
    Signal.BASE64_BLOCK: "AKR-01",
    Signal.HIDDEN_HTML: "AKR-01",
    Signal.TOOL_NAME_DUPLICATE: "AKR-05",
    Signal.TOOL_NAME_LOOKALIKE: "AKR-05",
    Signal.LONE_SURROGATE: "AKR-05",
}

#: Rule ID (the rule's ``name``) -> class ID.
RULE_CLASSES: dict[str, str] = {
    ToolPoisoning.name: "AKR-02",
}

#: The two kinds of ID ``class_of`` takes.
SIGNAL = "signal"
RULE = "rule"

_BY_ID = {c.id: c for c in CLASSES}


class UnknownIdentError(KeyError):
    """A signal or rule ID this version has no class for (a finding from a newer version)."""


def class_of(kind: str, ident: str) -> FindingClass:
    """The class of a signal (``kind`` ``"signal"``) or a rule (``"rule"``) by its ID.

    Raises :class:`UnknownIdentError` for an ID this version does not know; a caller that renders
    findings from a store written by another version says so rather than guess a class.
    """
    if kind == SIGNAL:
        try:
            return _BY_ID[SIGNAL_CLASSES[Signal(ident)]]
        except (ValueError, KeyError):
            raise UnknownIdentError(f"no class for signal {ident!r}") from None
    if kind == RULE:
        try:
            return _BY_ID[RULE_CLASSES[ident]]
        except (KeyError, TypeError):
            raise UnknownIdentError(f"no class for rule {ident!r}") from None
    raise ValueError(f"kind must be {SIGNAL!r} or {RULE!r}, not {kind!r}")


def class_label(kind: str, ident: Any) -> str | None:
    """``"AKR-NN Title"`` for an ID, or ``None`` when the ID is not one this version knows."""
    try:
        return class_of(kind, ident).label()
    except UnknownIdentError:
        return None


# -- the mapping file ---------------------------------------------------------------------------

MAPPING_RESOURCE = "finding-classes-mapping.yaml"

#: What ``ref`` may look like per framework: a number or an ID, never prose. As loose as the
#: spellings need and no looser; a framework not listed takes :data:`_BARE_ID`.
_BARE_ID = r"[A-Za-z0-9][A-Za-z0-9._:/\-]*"
REF_PATTERNS: dict[str, str] = {
    "acs-llm-pentest": r"A \d+(\.\d+)+",
    "owasp-mcp-top10": r"MCP\d{2}:\d{4}",
    "owasp-mcp-stg": r"MCPSTG-[A-Z]{2,5}-\d{2}",
    "cosai-mcp": r"MCP-T\d{1,2}",
    "owasp-llm-top10": r"LLM\d{2}(:\d{4})?",
    "mitre-atlas": r"AML\.[TM]\d{4}(\.\d{3})?",
    "iso-27001": r"(A\.)?\d+(\.\d+)*",
    "nis2-bsig": r"§ ?\d+[a-z]?( (Abs|Nr|S)\. ?\d+[a-z]?)*",
    "dora": r"Art\. ?\d+( ?\(\d+\))?( ?\([a-z]\))?",
    "eu-ai-act": r"Art\. ?\d+( ?\(\d+\))?|Annex [IVX]+|Recital \d+",
}

_HEAD_KEYS = {"frameworks", "classes"}
_FRAMEWORK_KEYS = {"id", "name", "version", "retrieved", "date", "note"}
_CLASS_KEYS = {"id", "entries"}
_ENTRY_KEYS = {"framework", "ref", "confirmed"}
_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]*")
_DATE_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")


class MappingError(ValueError):
    """A mapping file that cannot be used, with the file and the place in it."""


@dataclass(frozen=True, slots=True)
class Framework:
    id: str
    name: str
    version: str
    retrieved: str
    date: str | None
    note: str


@dataclass(frozen=True, slots=True)
class Entry:
    framework: str
    ref: str
    confirmed: bool


@dataclass(frozen=True, slots=True)
class Mapping:
    frameworks: tuple[Framework, ...]
    entries: dict[str, tuple[Entry, ...]]


def load_mapping(path: str | Path | None = None) -> Mapping:
    """Read and check the mapping file: the one in the package, or ``path``.

    Raises :class:`MappingError` naming the file and the place in it. Reading YAML needs the
    optional ``yaml`` extra, as for scenarios; rendering a class never needs this function.
    """
    if path is None:
        source = MAPPING_RESOURCE
        packaged = resources.files("mcp_kymograph").joinpath("data", MAPPING_RESOURCE)
        text = packaged.read_text("utf-8")
    else:
        source = str(path)
        try:
            text = Path(path).read_text("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise MappingError(f"{source}: cannot be read: {exc}") from None
    try:
        data = parse_yaml(text, source=source)
    except ScenarioError as exc:
        raise MappingError(str(exc)) from None
    return validate_mapping(data, source=source)


def validate_mapping(data: Any, *, source: str = "mapping") -> Mapping:
    """Check a parsed mapping against the class list; every error says where."""

    def fail(where: str, why: str) -> MappingError:
        return MappingError(f"{source}: {where}: {why}")

    def mapping_of(value: Any, where: str, keys: set[str]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise fail(where, "must be a mapping")
        for key in value:
            if key not in keys:
                raise fail(f"{where}.{key}", "unknown key")
        for key in sorted(keys):
            if key not in value:
                raise fail(where, f"missing key {key!r}")
        return value

    def list_of(value: Any, where: str) -> list[Any]:
        if not isinstance(value, list):
            raise fail(where, "must be a list")
        return value

    head = mapping_of(data, "(top level)", _HEAD_KEYS)

    frameworks: list[Framework] = []
    seen_frameworks: set[str] = set()
    for i, raw in enumerate(list_of(head["frameworks"], "frameworks")):
        where = f"frameworks[{i}]"
        item = mapping_of(raw, where, _FRAMEWORK_KEYS)
        for key in ("id", "name"):
            if not isinstance(item[key], str) or not item[key].strip():
                raise fail(f"{where}.{key}", "must be a non-empty string")
        if not isinstance(item["note"], str):
            raise fail(f"{where}.note", "must be a string")
        if not _ID_PATTERN.fullmatch(item["id"]):
            raise fail(f"{where}.id", f"{item['id']!r} is not a lowercase ID")
        if item["id"] in seen_frameworks:
            raise fail(f"{where}.id", f"framework {item['id']!r} listed twice")
        seen_frameworks.add(item["id"])
        version, retrieved, date = item["version"], item["retrieved"], item["date"]
        if not isinstance(version, str) or not version.strip():
            raise fail(f"{where}.version", "must be a non-empty string")
        if not (isinstance(retrieved, str) and _DATE_PATTERN.fullmatch(retrieved)):
            raise fail(f"{where}.retrieved", "must be a YYYY-MM-DD string")
        if date is not None and not (isinstance(date, str) and _DATE_PATTERN.fullmatch(date)):
            raise fail(f"{where}.date", "must be a YYYY-MM-DD string or null")
        frameworks.append(
            Framework(item["id"], item["name"], version, retrieved, date, item["note"])
        )

    known = {c.id for c in CLASSES}
    entries: dict[str, tuple[Entry, ...]] = {}
    for i, raw in enumerate(list_of(head["classes"], "classes")):
        where = f"classes[{i}]"
        item = mapping_of(raw, where, _CLASS_KEYS)
        class_id = item["id"]
        if not isinstance(class_id, str):
            raise fail(f"{where}.id", "must be a string")
        if class_id not in known:
            raise fail(f"{where}.id", f"unknown class {class_id!r}")
        if class_id in entries:
            raise fail(f"{where}.id", f"class {class_id!r} listed twice")
        found: list[Entry] = []
        for j, entry_raw in enumerate(list_of(item["entries"], f"{where}.entries")):
            at = f"{where}.entries[{j}]"
            entry = mapping_of(entry_raw, at, _ENTRY_KEYS)
            framework, ref, confirmed = entry["framework"], entry["ref"], entry["confirmed"]
            if not isinstance(framework, str):
                raise fail(f"{at}.framework", "must be a string")
            if framework not in seen_frameworks:
                raise fail(f"{at}.framework", f"unknown framework {framework!r}")
            pattern = REF_PATTERNS.get(framework, _BARE_ID)
            if not isinstance(ref, str) or not re.fullmatch(pattern, ref):
                raise fail(f"{at}.ref", f"{ref!r} is not a bare number or ID for {framework}")
            if not isinstance(confirmed, bool):
                raise fail(f"{at}.confirmed", "must be true or false")
            found.append(Entry(framework, ref, confirmed))
        entries[class_id] = tuple(found)
    for class_id in sorted(known - entries.keys()):
        raise fail("classes", f"class {class_id!r} is missing")
    return Mapping(tuple(frameworks), entries)
