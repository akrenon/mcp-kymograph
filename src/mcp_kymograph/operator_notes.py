"""The operator's private notes: a score, a status and the reason for each finding.

The tool keeps no reason for a decision about a finding and gives a finding no severity (store
schema 13): the operator's assessment belongs in these notes, which the operator writes, keeps
and reads, and which **no part of this tool reads** — no report, attestation, status, bundle,
export or web view (``tests/test_operator_notes.py`` asserts it over every module under
``src/``). The operator's assessment reaches the customer only as the separate part of the report
the operator writes and signs.

**Where they lie.** Beside the store of the engagement, named after it: ``<store>`` and
``.operator-notes`` and one of :data:`SUFFIXES` (:func:`beside`), the suffix in any case, as
:func:`load` takes it (``….operator-notes.YAML`` too). The name alone says whose they are, so
``engagement purge`` finds them among the entries beside the store, whatever the case of their
suffix, deletes each with the store without opening it, and ``purged.json`` names each as deleted,
under its own name. Notes kept anywhere else, or under another name, are the operator's to
delete.

**The format.** ``engagement`` (text) and ``findings``, a mapping from a finding's key (``fk-``
and 16 hex characters, :data:`KEY_PATTERN`) to ``{cvss, rationale, status}``. ``cvss`` is a CVSS
4.0 vector, checked against the specification's grammar and nothing more — no score is computed.
``status`` is one of :data:`STATUSES`. :func:`load` is the format's definition and its checker,
for the operator and the tests: read whole or refused whole, like a scenario, a manifest or an
engagement file — the same strict JSON and YAML front ends
(:func:`mcp_kymograph.scenario.parse_json`, :func:`~mcp_kymograph.scenario.parse_yaml`), keys
closed at every level, refused on the first thing that is wrong, with the file and the place. It
writes nothing, opens the file for reading only, and its errors name the place of a fault, never
a finding's text.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from mcp_kymograph.scenario import MAX_FILE_BYTES, ScenarioError, parse_json, parse_yaml

#: The name of the notes on disk, after the store's name and before the suffix.
NAME = "operator-notes"
#: The suffixes the notes may have, in the order :func:`beside` names them; :func:`load` takes
#: each in any case, and so does ``engagement purge``.
SUFFIXES = (".yaml", ".yml", ".json")


def beside(store: Path | str) -> tuple[Path, ...]:
    """Every path the notes of the engagement ``store`` holds may lie at: beside the store, its
    file name, ``.operator-notes`` and each of :data:`SUFFIXES` (``acme.sqlite`` →
    ``acme.sqlite.operator-notes.yaml``, ``….yml``, ``….json``). Names only, the suffix in lower
    case: nothing is opened or looked at, so a caller can delete them without reading them. A
    suffix in another case is the notes all the same (:func:`load`): a caller that looks for
    them on disk compares the suffix without its case."""
    store = Path(store)
    return tuple(store.with_name(f"{store.name}.{NAME}{suffix}") for suffix in SUFFIXES)


#: The statuses a finding may have in the notes: where the finding stands after the operator's
#: own assessment. ``partially_fixed`` is the one the specification names; the rest are proposed.
STATUSES = (
    "open",
    "confirmed",
    "false_positive",
    "accepted",
    "partially_fixed",
    "fixed",
)

#: The key of a finding in this file, as ``store findings`` shows it (``store.finding_key``). The
#: pattern is all this module knows of it: it does not make a key and does not look one up.
KEY_PATTERN = re.compile(r"fk-[0-9a-f]{16}")

#: Longest rationale taken, in characters.
MAX_RATIONALE_CHARS = 20000

#: CVSS 4.0 (FIRST, https://www.first.org/cvss/v4.0/specification-document): every metric with
#: the values it allows, in the order the vector writes them. The base metrics are mandatory.
_BASE: tuple[tuple[str, str], ...] = (
    ("AV", "NALP"),
    ("AC", "LH"),
    ("AT", "NP"),
    ("PR", "NLH"),
    ("UI", "NPA"),
    ("VC", "HLN"),
    ("VI", "HLN"),
    ("VA", "HLN"),
    ("SC", "HLN"),
    ("SI", "HLN"),
    ("SA", "HLN"),
)

#: The optional metrics — threat, environmental, supplemental — in the specification's order.
_OPTIONAL: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("E", ("X", "A", "P", "U")),
    ("CR", ("X", "H", "M", "L")),
    ("IR", ("X", "H", "M", "L")),
    ("AR", ("X", "H", "M", "L")),
    ("MAV", ("X", "N", "A", "L", "P")),
    ("MAC", ("X", "L", "H")),
    ("MAT", ("X", "N", "P")),
    ("MPR", ("X", "N", "L", "H")),
    ("MUI", ("X", "N", "P", "A")),
    ("MVC", ("X", "H", "L", "N")),
    ("MVI", ("X", "H", "L", "N")),
    ("MVA", ("X", "H", "L", "N")),
    ("MSC", ("X", "H", "L", "N")),
    ("MSI", ("X", "S", "H", "L", "N")),
    ("MSA", ("X", "S", "H", "L", "N")),
    ("S", ("X", "N", "P")),
    ("AU", ("X", "N", "Y")),
    ("R", ("X", "A", "U", "I")),
    ("V", ("X", "D", "C")),
    ("RE", ("X", "L", "M", "H")),
    ("U", ("X", "Clear", "Green", "Amber", "Red")),
)

_PREFIX = "CVSS:4.0/"
_ROOT_KEYS = frozenset({"engagement", "findings"})
_FINDING_KEYS = frozenset({"cvss", "rationale", "status"})


class OperatorNotesError(ValueError):
    """Operator's notes that are not: the message names the file and the place."""


@dataclass(frozen=True, slots=True)
class FindingNotes:
    """The operator's notes on one finding, as the file gave them."""

    cvss: str
    rationale: str
    status: str


@dataclass(frozen=True, slots=True)
class OperatorNotes:
    """The operator's notes, loaded."""

    engagement: str
    findings: Mapping[str, FindingNotes]


def load(path: Path | str) -> OperatorNotes:
    """Read, parse and validate one notes file, or raise :class:`OperatorNotesError`."""
    path = Path(path)
    source = str(path)
    suffix = path.suffix.lower()
    if suffix not in (".json", ".yaml", ".yml"):
        raise OperatorNotesError(f"{source}: unknown suffix {suffix!r}; use .yaml, .yml or .json")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise OperatorNotesError(f"{source}: cannot read: {exc.strerror or exc}") from None
    if len(raw) > MAX_FILE_BYTES:
        raise OperatorNotesError(f"{source}: larger than {MAX_FILE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OperatorNotesError(f"{source}: not UTF-8 at byte {exc.start}") from None
    try:
        data = (
            parse_json(text, source=source)
            if suffix == ".json"
            else parse_yaml(text, source=source)
        )
    except ScenarioError as refusal:
        raise OperatorNotesError(str(refusal)) from None
    return build(data, source=source)


def build(data: Any, *, source: str) -> OperatorNotes:
    """Validate parsed data as the operator's notes; the first fault is raised, with its place."""
    if not isinstance(data, dict):
        raise OperatorNotesError(
            f"{source}: the operator's notes are a mapping with engagement and findings"
        )
    _closed(data, _ROOT_KEYS, source, "")
    for key in sorted(_ROOT_KEYS):
        if key not in data:
            raise OperatorNotesError(f"{source}: {key} is missing")
    engagement = data["engagement"]
    if not isinstance(engagement, str) or not engagement.strip():
        raise OperatorNotesError(f"{source}: engagement is not a non-empty text")
    findings = data["findings"]
    if not isinstance(findings, dict):
        raise OperatorNotesError(
            f"{source}: findings is not a mapping from a finding key to the notes on it"
        )
    noted: dict[str, FindingNotes] = {}
    for key, item in findings.items():
        if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
            raise OperatorNotesError(
                f"{source}: a key of findings is not a finding key (fk- and 16 hex characters, "
                "as store findings shows it)"
            )
        where = f"findings['{key}']"
        if not isinstance(item, dict):
            raise OperatorNotesError(
                f"{source}: {where} is not a mapping of cvss, rationale and status"
            )
        _closed(item, _FINDING_KEYS, source, where)
        for name in sorted(_FINDING_KEYS):
            if name not in item:
                raise OperatorNotesError(f"{source}: {where}.{name} is missing")
        problem = cvss_problem(item["cvss"])
        if problem is not None:
            raise OperatorNotesError(f"{source}: {where}.cvss: {problem}")
        rationale = item["rationale"]
        if not isinstance(rationale, str) or not rationale.strip():
            raise OperatorNotesError(f"{source}: {where}.rationale is not a non-empty text")
        if len(rationale) > MAX_RATIONALE_CHARS:
            raise OperatorNotesError(
                f"{source}: {where}.rationale is longer than {MAX_RATIONALE_CHARS} characters"
            )
        status = item["status"]
        if not isinstance(status, str) or status not in STATUSES:
            raise OperatorNotesError(
                f"{source}: {where}.status is not one of {', '.join(STATUSES)}"
            )
        noted[key] = FindingNotes(item["cvss"], rationale, status)
    return OperatorNotes(engagement, MappingProxyType(noted))


def _closed(mapping: dict, allowed: frozenset[str], source: str, where: str) -> None:
    for key in mapping:
        if key not in allowed:
            # Where the key stands, never what it says: a sentence put one level too deep is
            # the usual way to get here, and it may hold what the file is private for.
            at = f"{where}: " if where else "top level: "
            raise OperatorNotesError(
                f"{source}: {at}a key that is not allowed here; "
                f"allowed: {', '.join(sorted(allowed))}"
            )


def cvss_problem(vector: Any) -> str | None:
    """Why ``vector`` is not a CVSS 4.0 vector, or None.

    The grammar: the prefix ``CVSS:4.0/``, then the base metrics AV, AC, AT, PR, UI, VC, VI, VA,
    SC, SI and SA, all of them, in this order, then any of the optional metrics (threat,
    environmental, supplemental) in the specification's order, each at most once; every value one
    the metric allows. Values are case-sensitive, and nothing may follow or surround the vector.
    """
    if not isinstance(vector, str):
        return "is not a text"
    if not vector.startswith(_PREFIX):
        return f"does not start with {_PREFIX}"
    parts = vector[len(_PREFIX) :].split("/")
    base = parts[: len(_BASE)]
    for number, (name, allowed) in enumerate(_BASE):
        if number >= len(base):
            return f"base metric {name} is missing"
        problem = _metric_problem(base[number], name, tuple(allowed))
        if problem is not None:
            return problem
    position = 0
    for part in parts[len(_BASE) :]:
        name = part.partition(":")[0]
        order = [candidate for candidate, _ in _OPTIONAL]
        if name not in order:
            known = [candidate for candidate, _ in _BASE]
            if name in known:
                return f"metric {name} is repeated or out of its place"
            return f"metric {_short(name)} is not a CVSS 4.0 metric"
        index = order.index(name)
        if index < position:
            return f"metric {name} is repeated or out of the specification's order"
        problem = _metric_problem(part, name, _OPTIONAL[index][1])
        if problem is not None:
            return problem
        position = index + 1
    return None


def _metric_problem(part: str, name: str, allowed: tuple[str, ...]) -> str | None:
    metric, colon, value = part.partition(":")
    if metric != name or not colon:
        return f"expected metric {name} as {name}:VALUE, found {_short(part)}"
    if value not in allowed:
        return f"metric {name} has value {_short(value)}, allowed: {', '.join(allowed)}"
    return None


def _short(text: str) -> str:
    """A fragment of the file, cut short and shown without anything a terminal would act on."""
    cut = text[:24] + ("…" if len(text) > 24 else "")
    return repr(cut)
