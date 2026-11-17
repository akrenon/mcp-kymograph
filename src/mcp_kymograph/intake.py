"""Intake: what the customer operates, asked in a questionnaire and turned into a draft file.

The operator cannot write an engagement file without knowing what exists
(docs/engagements.md, 1). ``engagement intake`` hands the customer a questionnaire —
YAML with comments, or the same fields as a plain text form for a customer who does not write
YAML — reads the answers back, and writes a *draft* engagement file from them: every field it can
derive filled in, every field it cannot left as a bracketed placeholder, and a list of what is
still missing. A draft loads and is refused by the gate (condition ``draft``): it can be shown and
agreed on, never run under.

The draft is a file of the second version (docs/engagements.md, 2). Beside ``servers``,
``constraints`` and ``notes``, which go under ``declared``, the questionnaire asks the fields only
that version has (:data:`FIELD_ORDER`): the end customer (``customer``, which the first version
called the customer), the agency, the tools, when to stop, whom to call, the values to be
replaced, the salt's variable, the canaries, the receiver and the token passthrough. Those answers
go into the fields of the file, not under ``declared``: ``known_values`` and the names of the
variables are removed from whatever may be handed on, ``declared`` is not.

**The answers are claims.** What the customer wrote goes under the draft's ``declared`` unchanged,
and nothing here checks it against the world: no name is resolved, no URL is fetched. The one
thing taken from the answers into the rest of the file is a target's host, port and path, read
off a URL in ``reached_how`` — a reading of the customer's words, to be agreed like every other
line of the draft, never a fact about the server.

**Two readers, one strict and one lenient.** YAML and JSON answers are read whole or refused
whole, with the file and the place, by the same front ends as an engagement file. The text form
(``.txt``) is the one lenient reader in the project: a line it can place goes to its field, a
line it cannot place is kept verbatim under ``notes``, and nothing is dropped, except a line
with a character of the categories control (Cc), format (Cf), surrogate (Cs), private use (Co)
or unassigned (Cn): :func:`draft` refuses that one, naming the categories, and it is kept nowhere.
It is lenient because a customer filling in a form is not writing a file format, and it may be,
because what it reads feeds nothing but a draft, which the gate refuses until a person has
filled it in. The exception is a line of the second version's fields: it is placed without being
checked, and :func:`draft` refuses it with its place if it is wrong. Never kept under ``notes``,
because it may be a secret (a known value, a prefix).

**A line directly under a secret field is refused.** A key written over several lines, or a value
put on the line below an empty label, would leave its later lines as free text. So a line that
no field takes and that stands directly under a line of a field of :data:`SECRET_FIELDS`, with no
blank line between, is refused like a line with an unprintable character, by its number and that
field, and kept nowhere; so is every line after it up to the next blank line or the next line a
field takes. The limit is the blank line: after one, a line is free text again, even if it is
part of a key. A key belongs in none of these answers.

**An empty answer is no answer.** ``""``, an empty list and a YAML key left without a value are
what the questionnaire hands out, and are read as the question left open: dropped, so the
questionnaire read back as it was handed out is no answers at all.

This module makes no network connection and resolves no name. :func:`read_answers` reads one
file; nothing else here touches the filesystem — writing what it returns is the caller's.
"""

from __future__ import annotations

import copy
import json
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp_kymograph import engagement
from mcp_kymograph.authorization import plain_http_refusal, split_target
from mcp_kymograph.credentials import ENV_NAME
from mcp_kymograph.engagement import (
    CANARY_KINDS,
    CONSTRAINT_KEYS,
    DECLARED_KEYS,
    DEFAULT_PORTS,
    ENGAGEMENT_ID,
    FORMAT_VERSION_2,
    MAX_RETENTION_SECONDS,
    MIN_KNOWN_VALUE,
    PASSTHROUGH_METHODS,
    PLACEHOLDER_SHAPE,
    RECEIVER_VARIANTS,
    TARGET_PATH,
    EngagementError,
    good_receiver_address,
    good_receiver_prefix,
    good_receiver_ssh,
    has_scope_id,
    safe_text,
)
from mcp_kymograph.scenario import MAX_FILE_BYTES, ScenarioError, parse_json, parse_yaml

#: The questions about one server, in the order they are asked. The keys of an engagement file's
#: ``declared.servers[]`` but ``entry``, which names a manifest entry and is the operator's to
#: fill in, not the customer's.
SERVER_FIELDS = (
    "name",
    "reached_how",
    "transport",
    "version_or_commit",
    "clients_in_use",
    "owner_contact",
    "may_be_run_locally",
    "change_freeze",
)
#: The questions about the engagement as a whole: ``declared.constraints``.
CONSTRAINT_FIELDS = ("hours", "rate", "do_not")
#: The answers that are lists in the questionnaire. Any answer may be given either way, as
#: ``declared`` takes it; these are the ones the text form adds to when the line is repeated.
LIST_FIELDS = frozenset(
    {
        "clients_in_use",
        "do_not",
        "notes",
        "agency_contacts",
        "tools",
        "abort_criteria",
        "known_values",
        "canaries",
    }
)
#: The questions about the fields only a file of the second version has, in the order they are
#: asked; the top-level keys of the answers, beside ``servers``, ``constraints`` and ``notes``.
#: Those that are lists in the file are lists here, one item for each line; the structured ones
#: take their parts after a ``|``: a contact as ``name | role | reach``, a tool as
#: ``name | writes`` or ``name | read-only``, a canary as ``id | kind | where`` and, for a file,
#: ``| path``.
FIELD_ORDER = (
    "customer",
    "agency",
    "agency_contacts",
    "tools",
    "abort_criteria",
    "emergency_name",
    "emergency_reach",
    "known_values",
    "salt_env",
    "canaries",
    "receiver_variant",
    "receiver_address",
    "receiver_path_prefix",
    "receiver_key_env",
    "receiver_ssh",
    "receiver_retention_seconds",
    "token_passthrough",
)


HEADER = "Please answer what you can; leave the rest. Nothing here is checked against your systems."

#: What each question means, as the questionnaire says it beside the field.
_HINTS = {
    "name": "how you refer to it",
    "reached_how": 'a URL, or "started by the client as a process"',
    "transport": "stdio | streamable-http | don't know",
    "version_or_commit": "what you believe is deployed",
    "clients_in_use": "which MCP clients talk to it, as far as you know",
    "owner_contact": "who answers for it, and how to reach them",
    "may_be_run_locally": "yes, if you can give us an image or the source | no",
    "change_freeze": "dates during which nothing will be deployed",
    "hours": "when runs may happen",
    "rate": "how often, if it matters",
    "do_not": "anything that must not be done, in your words",
    "notes": "anything else we should know",
    "customer": "the name of the end customer",
    "agency": "the agency that orders this, if there is one",
    "agency_contacts": 'who at the agency, as "name | role | reach"',
    "tools": 'each tool the test may call, as "name | writes" or "name | read-only"',
    "abort_criteria": "when the test must stop at once, one sentence each",
    "emergency_name": "whom to call if something goes wrong",
    "emergency_reach": "how to reach them",
    "known_values": "values that must never be kept as they are; they are not shown again",
    "salt_env": "the NAME of the environment variable that holds the salt, not the salt",
    "canaries": 'each canary placed, as "id | kind | where" and for a file "| path"',
    "receiver_variant": "local | reachable",
    "receiver_address": "host or host and port of the receiver, no scheme or path",
    "receiver_path_prefix": "the receiver's path prefix, 22 to 128 of A-Z a-z 0-9 _ -",
    "receiver_key_env": "the NAME of the environment variable that holds the receiver's key",
    "receiver_ssh": (
        "a reference to the receiver's host, as user@host and a port, each optional, or <NAME>"
    ),
    "receiver_retention_seconds": "how long the receiver keeps what it receives, in seconds",
    "token_passthrough": "redirect | upstream_log",
}

#: The answers that may be a secret, or hold one: no message about them repeats what was written,
#: not even a number, and the text form never keeps a line of them under ``notes``.
SECRET_FIELDS = frozenset(
    (
        "known_values",
        "salt_env",
        "receiver_key_env",
        "receiver_ssh",
        "receiver_path_prefix",
        "emergency_reach",
    )
)

#: The text form's label for each field. ``Client in use``, ``Do not`` and ``Note`` are singular
#: because the line is repeated for each one.
_LABELS = {
    "name": "Server name",
    "reached_how": "Reached how",
    "transport": "Transport",
    "version_or_commit": "Version or commit",
    "clients_in_use": "Client in use",
    "owner_contact": "Owner contact",
    "may_be_run_locally": "May be run locally",
    "change_freeze": "Change freeze",
    "hours": "Hours",
    "rate": "Rate",
    "do_not": "Do not",
    "notes": "Note",
    "customer": "Customer",
    "agency": "Agency",
    "agency_contacts": "Agency contact",
    "tools": "Tool",
    "abort_criteria": "Stop if",
    "emergency_name": "Emergency contact",
    "emergency_reach": "Emergency reach",
    "known_values": "Known value",
    "salt_env": "Salt variable",
    "canaries": "Canary",
    "receiver_variant": "Receiver",
    "receiver_address": "Receiver address",
    "receiver_path_prefix": "Receiver path prefix",
    "receiver_key_env": "Receiver key variable",
    "receiver_ssh": "Receiver ssh",
    "receiver_retention_seconds": "Receiver retention seconds",
    "token_passthrough": "Token passthrough",
}

#: The column the YAML questionnaire's comments start at.
_COMMENT_COLUMN = 29


class IntakeError(ValueError):
    """Answers that cannot be read, with the file and the place in them.

    Shaped like :class:`mcp_kymograph.engagement.EngagementError`: the file is kept apart from
    the reason, as ``source``.
    """

    def __init__(self, reason: str, *, source: str | None = None) -> None:
        super().__init__(reason if source is None else f"{source}: {reason}")
        self.source = source
        self.reason = reason


class _Invalid(Exception):
    """One place in the answers that is wrong; :func:`read_answers` adds the file."""

    def __init__(self, where: str, message: str) -> None:
        super().__init__(message)
        self.where = where
        self.message = message


@dataclass(frozen=True, slots=True)
class Answers:
    """The customer's answers, in the shape of an engagement file's ``declared``.

    ``data`` holds what was answered and nothing else: a question left open is not a key, a
    server with nothing answered is not in the list, and answers that were given are as written.
    """

    source: str
    #: ``yaml``, ``json`` or ``text``: which reader read it.
    form: str
    data: dict[str, Any]
    #: The text form only: the numbers (from 1) of the lines no field took, each kept verbatim
    #: under ``notes``.
    unplaced: tuple[int, ...] = ()
    #: The answers to :data:`FIELD_ORDER`, as written: a string, or a list of strings for the
    #: list fields (the text form may hold a list for a field that takes one answer; :func:`draft`
    #: refuses that).
    fields: dict[str, Any] = dataclass_field(default_factory=dict)
    #: The text form only: the number (from 1) of each line that holds a character a terminal
    #: would act on, and the field its label names (``""`` for none); and of each line no field
    #: takes that begins like the label of a field of :data:`SECRET_FIELDS`, that field.
    #: Also each line no field takes that stands directly under a line of a field of
    #: :data:`SECRET_FIELDS`, that field. The line is kept nowhere; :func:`draft` refuses it by
    #: its place.
    refused: tuple[tuple[int, str], ...] = ()
    #: For each refused line, in the same order, the categories of the characters it holds, in
    #: the order of :data:`_CATEGORY_WORDS`; never the characters themselves. Empty for a line
    #: that begins like a secret field's label, and :data:`_BELOW_SECRET` for a line directly
    #: under a secret field's.
    refused_categories: tuple[tuple[str, ...], ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.data and not self.fields


# -- the questionnaire -------------------------------------------------------------------------


def questionnaire() -> str:
    """The questionnaire as YAML with comments: what ``engagement intake --out FILE`` writes.

    Written as text, so writing it needs no YAML library; every answer is an empty string or an
    empty list, so it reads back through :func:`read_answers` as no answers at all.
    """
    lines = [
        f"# {HEADER}",
        "#",
        '# Write each answer between the quotes, and a list as ["first", "second"]. Keep the',
        "# quotes: an answer like 3.1 or true without them is read as a number and refused.",
        '# For a second server, copy the block from "- name" down and fill in the copy.',
        '# Where a line asks for parts, as "name | role", separate them with a vertical bar.',
        "servers:",
    ]
    for index, field in enumerate(SERVER_FIELDS):
        prefix = "  - " if index == 0 else "    "
        lines.append(_yaml_line(prefix, field))
    lines.append("constraints:")
    lines += [_yaml_line("  ", field) for field in CONSTRAINT_FIELDS]
    lines.append(_yaml_line("", "notes"))
    lines += [_yaml_line("", field) for field in FIELD_ORDER]
    return "\n".join(lines) + "\n"


def _yaml_line(prefix: str, field: str) -> str:
    empty = "[]" if field in LIST_FIELDS else '""'
    return f"{prefix}{field}: {empty}".ljust(_COMMENT_COLUMN - 1) + f" # {_HINTS[field]}"


def questionnaire_text() -> str:
    """The same questions as a plain text form, for a customer who does not write YAML.

    One ``Label: answer`` line per field: the server's lines as one block, a blank line, the
    lines about the engagement as a whole. A second server is a copy of the block after a blank
    line; a second client, a second thing not to do or a second note is the line repeated. The
    instructions above the fields hold no colon, so none of them can be read as an answer, and
    :func:`read_answers` passes over every line of them that comes back as it was handed out.
    """
    lines = [
        HEADER,
        "",
        "Write each answer after the colon, on the same line. For more than one client, more",
        "than one thing that must not be done, or more than one note, repeat the line. For a",
        "second server, copy the server's lines and leave a blank line before the copy.",
        "Anything that fits no line, write on a line of its own after a blank line; it is kept as",
        "you wrote it.",
        "Where a line asks for parts, separate them with a vertical bar.",
        "",
        "What the lines ask",
        *(f"  {_LABELS[field]} - {_HINTS[field]}" for field in _TEXT_ORDER),
        "",
        *(f"{_LABELS[field]}:" for field in SERVER_FIELDS),
        "",
        *(f"{_LABELS[field]}:" for field in (*CONSTRAINT_FIELDS, "notes")),
        "",
        *(f"{_LABELS[field]}:" for field in FIELD_ORDER),
    ]
    return "\n".join(lines) + "\n"


_TEXT_ORDER = (*SERVER_FIELDS, *CONSTRAINT_FIELDS, "notes", *FIELD_ORDER)


def _normal(label: str) -> str:
    return " ".join(label.lower().replace("_", " ").replace("-", " ").split())


#: Every spelling of a label the text form takes, normalised: the label as handed out, the
#: field's key, and the plural of the repeated ones.
_ALIASES: dict[str, str] = {}
for _field in _TEXT_ORDER:
    _ALIASES[_normal(_LABELS[_field])] = _field
    _ALIASES[_normal(_field)] = _field
_ALIASES.update({"clients in use": "clients_in_use", "do nots": "do_not", "notes": "notes"})
del _field

#: What :attr:`Answers.refused_categories` holds for a line refused for standing directly under a
#: line of a secret field: no category, but not the empty tuple of a near label either.
_BELOW_SECRET = ("below a secret field",)

#: The instruction lines of the text form, stripped: passed over when they come back unchanged.
_INSTRUCTIONS = frozenset(
    stripped
    for stripped in (line.strip() for line in questionnaire_text().splitlines())
    if stripped and ":" not in stripped
)

#: ``Label: answer``. The label is letters, spaces, ``_`` and ``-``; the answer is the rest of
#: the line after the first colon.
_FIELD_LINE = re.compile(r"\s*([A-Za-z][A-Za-z _-]*?)\s*:(.*)")


# -- reading the answers -----------------------------------------------------------------------


def read_answers(path: str | Path) -> Answers:
    """Read the customer's answers, or raise :class:`IntakeError`.

    ``.yaml``, ``.yml`` and ``.json`` are read whole or refused whole, with the file and the
    place: keys closed at every level, every answer a string or a list of strings. ``.txt`` is
    the text form of :func:`questionnaire_text`, read leniently (:func:`_read_text`).
    """
    path = Path(path)
    source = str(path)
    suffix = path.suffix.lower()
    if suffix not in (".json", ".yaml", ".yml", ".txt"):
        raise IntakeError(
            f"unknown suffix {suffix!r}; use .yaml, .yml or .json, or .txt for the text form",
            source=source,
        )
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise IntakeError(f"cannot read: {exc.strerror or exc}", source=source) from None
    if len(raw) > MAX_FILE_BYTES:
        raise IntakeError(f"larger than {MAX_FILE_BYTES} bytes", source=source)
    try:
        # A text form saved by a plain editor may begin with a byte order mark; it marks the
        # encoding and is no part of any line.
        text = raw.decode("utf-8-sig" if suffix == ".txt" else "utf-8")
    except UnicodeDecodeError as exc:
        raise IntakeError(f"not UTF-8 at byte {exc.start}", source=source) from None
    if suffix == ".txt":
        data, fields, unplaced, refused, categories = _read_text(text)
        return Answers(
            source=source,
            form="text",
            data=data,
            unplaced=unplaced,
            fields=fields,
            refused=refused,
            refused_categories=categories,
        )
    try:
        parsed = (
            parse_json(text, source=source)
            if suffix == ".json"
            else parse_yaml(text, source=source)
        )
    except ScenarioError as exc:
        reason = str(exc).removeprefix(f"{source}: ")
        reason = reason.replace("write the scenario", "write the answers").replace(
            "in a scenario", "in the answers"
        )
        raise IntakeError(reason, source=source) from None
    try:
        data, fields = _shape(parsed)
    except _Invalid as invalid:
        where = f"{invalid.where}: " if invalid.where else ""
        raise IntakeError(f"{where}{invalid.message}", source=source) from None
    return Answers(
        source=source, form="json" if suffix == ".json" else "yaml", data=data, fields=fields
    )


def _shape(data: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """The questionnaire's shape, strictly; what was answered, with every open question left out:
    the answers that go under ``declared`` and the answers to :data:`FIELD_ORDER`. Raises
    :class:`_Invalid` with the place."""
    if not isinstance(data, dict):
        raise _Invalid("", "the answers must be a mapping with servers, constraints and notes")
    _only(data, DECLARED_KEYS | frozenset(FIELD_ORDER), "")
    answered: dict[str, Any] = {}
    fields: dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        if key in FIELD_ORDER:
            given = _answer(value, key, secret=key in SECRET_FIELDS)
            if isinstance(given, str) and key in LIST_FIELDS:
                given = [given]
            if given is None:
                continue
            given = _without_placeholders(given, key)
            if given:
                fields[key] = given
        elif key == "servers":
            if not isinstance(value, list):
                raise _Invalid("servers", "expected a list, one item for each server")
            servers = []
            for index, server in enumerate(value):
                where = f"servers[{index}]"
                if not isinstance(server, dict):
                    raise _Invalid(where, f"expected a mapping with {', '.join(SERVER_FIELDS)}")
                _only(server, frozenset(SERVER_FIELDS), where)
                kept = _answered(server, where)
                if kept:
                    servers.append(kept)
            if servers:
                answered["servers"] = servers
        elif key == "constraints":
            if not isinstance(value, dict):
                raise _Invalid(
                    "constraints", f"expected a mapping with {', '.join(CONSTRAINT_FIELDS)}"
                )
            _only(value, CONSTRAINT_KEYS, "constraints")
            kept = _answered(value, "constraints")
            if kept:
                answered["constraints"] = kept
        else:
            if not isinstance(value, list):
                raise _Invalid("notes", 'expected a list of strings, as ["first", "second"]')
            notes = _answer(value, "notes")
            if notes:
                answered["notes"] = notes
    _check_fields(fields)
    return answered, fields


def _answered(mapping: dict, where: str) -> dict[str, Any]:
    kept: dict[str, Any] = {}
    for key, value in mapping.items():
        answer = _answer(value, f"{where}.{key}")
        if answer:
            kept[key] = answer
    return kept


def _answer(value: Any, where: str, *, secret: bool = False) -> str | list[str] | None:
    """A string, or a list of strings, as written; None, ``""`` and ``[]`` are no answer, and an
    empty item of a list is dropped from it. For a secret answer the message says where and what
    form, and never what was written."""
    if value is None or isinstance(value, str):
        return value or None
    if isinstance(value, list):
        items: list[str] = []
        for index, item in enumerate(value):
            if item is None or item == "":
                continue
            if not isinstance(item, str):
                message = _not_secret_text() if secret else _not_text(item)
                raise _Invalid(f"{where}[{index}]", message)
            items.append(item)
        return items or None
    raise _Invalid(where, _not_secret_text() if secret else _not_text(value))


def _not_secret_text() -> str:
    return "expected a string, or a list of strings, in quotes: not a number or a yes-or-no value"


def _not_text(value: Any) -> str:
    if isinstance(value, (bool, int, float)):
        # As the customer will have typed it: true, not True.
        written = json.dumps(value)
        return f'{written} is not text: put the answer in quotes, as "{written}"'
    return "expected a string or a list of strings"


def _only(mapping: dict, allowed: frozenset[str], where: str) -> None:
    for key in mapping:
        if key not in allowed:
            raise _Invalid(
                where, f"unknown key {key!r}; expected one of {', '.join(sorted(allowed))}"
            )


def _read_text(
    text: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    tuple[int, ...],
    tuple[tuple[int, str], ...],
    tuple[tuple[str, ...], ...],
]:
    """The text form, leniently: every line it can place goes to its field, every line it
    cannot goes to ``notes`` as it was written. Never refuses, but notes the lines that
    :func:`draft` must, with the categories of the characters each holds.

    A line no field takes is treated like one with an unprintable character when, with only its
    letters left and in lower case, it begins with the label or the key of a field of
    :data:`SECRET_FIELDS` likewise cut down (``Known value 2: x``, ``- Known value: x``,
    ``KNOWN-VALUES = x``): it may be a secret written a little wrong, and a note would carry it
    into the store and the bundle. It is noted by its number and that field, with no categories.
    False alarms are meant: ``Known values are rotated monthly`` is refused too, the safe way.

    A line is blank only when, without its line ending, it is nothing but spaces and tabs: a
    line of other characters that Python counts as white space (``\\x0b``, ``\\x1c``,
    ``\\x85``) is not blank, and is refused as every line with an unprintable character is.

    A line is placed when it is ``Label: answer`` with a label of the form (any case; ``_`` or
    ``-`` for a space; the field's key) and holds no character that has no business on a
    terminal. A line with one is never placed and never kept, not under ``notes`` either, whatever
    its label: it may hold a secret, and a label cut by such a character names no field. Only its
    number is noted, with the field its label names once those characters are taken out (or
    none), for :func:`draft` to refuse. A blank line ends a server's block; a server line
    after it, or ``Server name`` with an answer in a block that has one, begins the next server.
    A second answer to a question that takes one answer is not placed. A line of a question in
    :data:`FIELD_ORDER` is placed unchecked, and a second answer to one that takes one is kept
    with the first, as a list, for :func:`draft` to refuse: such a line may hold a secret, which
    belongs in no note. An instruction line of
    :func:`questionnaire_text` that comes back unchanged is passed over.

    A line no field takes that stands directly under a line of a field of :data:`SECRET_FIELDS`
    (also one whose label is empty, and also the third, fourth and every further line) is
    refused and kept nowhere, noted by its number and that field with :data:`_BELOW_SECRET`: it
    may be the rest of a key or of a value put on the next line. A blank line ends this, and so
    does a line that another field takes (``Note:`` too); a further line of a secret field starts
    it again. A line that begins like a secret label or holds an unprintable character keeps its
    own refusal and, if its label names a secret field, starts it too. Behind a blank line a line
    is free text again, even when it belongs to a key: the limit of this rule.

    Lines end at ``\\n``, and one ``\\r`` before it is taken as part of the line ending; anything
    else that a reader might take for a line break stays inside its line.
    """
    servers: list[dict[str, Any]] = []
    constraints: dict[str, Any] = {}
    fields: dict[str, Any] = {}
    notes: list[str] = []
    unplaced: list[int] = []
    refused: list[tuple[int, str]] = []
    categories: list[tuple[str, ...]] = []
    current: dict[str, Any] | None = None
    open_block = False
    below: str | None = None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, start=1):
        if line.endswith("\r"):
            line = line[:-1]
        if not line.strip(" \t"):
            open_block = False
            below = None
            continue
        stripped = line.strip()
        field, answer = _placed(line)
        if not _printable(line):
            named = _label_field(safe_text(line)) or ""
            refused.append((number, named))
            categories.append(_categories(line))
            if named in SECRET_FIELDS:
                below = named
            continue
        if field is None:
            if stripped in _INSTRUCTIONS and _printable(line):
                continue
            near = _near_secret_label(line)
            if near is not None:
                refused.append((number, near))
                categories.append(())
                below = near
                continue
            if below is not None:
                refused.append((number, below))
                categories.append(_BELOW_SECRET)
                continue
            notes.append(line)
            unplaced.append(number)
            continue
        below = field if field in SECRET_FIELDS else None
        if field in SERVER_FIELDS:
            if (
                current is None
                or not open_block
                or (field == "name" and answer and "name" in current)
            ):
                current = {}
                servers.append(current)
                open_block = True
            target = current
        elif field == "notes":
            if answer:
                notes.append(answer)
            continue
        elif field in FIELD_ORDER:
            if answer and not _is_placeholder(answer, field):
                if field in LIST_FIELDS:
                    fields.setdefault(field, []).append(answer)
                elif field in fields:
                    kept = fields[field]
                    fields[field] = [*kept, answer] if isinstance(kept, list) else [kept, answer]
                else:
                    fields[field] = answer
            continue
        else:
            target = constraints
        if not answer:
            continue
        if field in LIST_FIELDS:
            target.setdefault(field, []).append(answer)
        elif field in target:
            notes.append(line)
            unplaced.append(number)
        else:
            target[field] = answer
    data: dict[str, Any] = {}
    kept = [_ordered(server, SERVER_FIELDS) for server in servers if server]
    if kept:
        data["servers"] = kept
    if constraints:
        data["constraints"] = _ordered(constraints, CONSTRAINT_FIELDS)
    if notes:
        data["notes"] = notes
    return (
        data,
        _ordered(fields, FIELD_ORDER),
        tuple(unplaced),
        tuple(refused),
        tuple(categories),
    )


def _placed(line: str) -> tuple[str | None, str]:
    if not _printable(line):
        return None, ""
    match = _FIELD_LINE.fullmatch(line)
    if match is None:
        return None, ""
    field = _ALIASES.get(_normal(match.group(1)))
    if field is None:
        return None, ""
    return field, match.group(2).strip()


def _letters(text: str) -> str:
    """Only the letters a-z of a text, once it is decomposed (NFKD) and case folded: accents,
    combining marks, full width forms and the long s all come down to plain letters."""
    folded = unicodedata.normalize("NFKD", text).casefold()
    return "".join(character for character in folded if "a" <= character <= "z")


#: For each field of :data:`SECRET_FIELDS`, its label and its key as :func:`_letters` leaves them.
_SECRET_STARTS = tuple(
    (_letters(spelling), field)
    for field in sorted(SECRET_FIELDS)
    for spelling in (_LABELS[field], field)
)

#: Shorter starts of the same fields, the field's own words and no others: ``Salt: <value>``
#: names no label, but is plainly meant for ``salt_env``. Words that merely suggest a secret
#: (``Password``, ``Token``) are not here: this finds the form's labels, not secrets.
_SHORT_STARTS = tuple(
    (_letters(spelling), field)
    for field, spellings in (
        ("known_values", ("Known",)),
        ("salt_env", ("Salt",)),
        ("receiver_key_env", ("Receiver key", "Key")),
        (
            "receiver_path_prefix",
            ("Receiver path", "Receiver prefix", "Path prefix", "Prefix", "Path"),
        ),
        ("receiver_ssh", ("Receiver ssh", "SSH")),
        ("emergency_reach", ("Emergency",)),
    )
    for spelling in spellings
)


def _near_secret_label(line: str) -> str | None:
    """The field of :data:`SECRET_FIELDS` whose label, key or short start (:data:`_SHORT_STARTS`)
    the line begins with, once only the letters of both are compared, or None. The longest such
    start wins."""
    letters = _letters(line)
    found = [
        (len(start), field)
        for start, field in (*_SECRET_STARTS, *_SHORT_STARTS)
        if letters.startswith(start)
    ]
    return max(found)[1] if found else None


def _label_field(line: str) -> str | None:
    """The field a line's label names, whatever the rest of the line holds."""
    match = _FIELD_LINE.fullmatch(line)
    return None if match is None else _ALIASES.get(_normal(match.group(1)))


def _printable(line: str) -> bool:
    """No character a terminal would act on rather than show — none that
    :func:`engagement.safe_text` would take out; a tab is taken as a space."""
    spaced = line.replace("\t", " ")
    return safe_text(spaced) == spaced


#: The categories :func:`_printable` refuses, in the order a message names them.
_CATEGORY_WORDS = {
    "Cc": "control",
    "Cf": "format",
    "Cs": "surrogate",
    "Co": "private use",
    "Cn": "unassigned",
}


def _categories(line: str) -> tuple[str, ...]:
    """The refused categories of the characters in a line, once each, in a fixed order."""
    found = {unicodedata.category(character) for character in line.replace("\t", " ")}
    return tuple(code for code in _CATEGORY_WORDS if code in found)


def _ordered(mapping: dict[str, Any], order: tuple[str, ...]) -> dict[str, Any]:
    return {key: mapping[key] for key in order if key in mapping}


# -- the second version's answers ----------------------------------------------------------------


#: The words of ``tools`` that say whether a tool writes.
_WRITES = frozenset({"writes", "write"})
_READS = frozenset({"read-only", "read only", "reads", "read"})


def _is_placeholder(text: str, key: str) -> bool:
    """Wholly bracketed text, as ``[don't know]``; but not an address the field's reader takes
    (``[2001:db8::7]``), nor one with a scope ID, which is kept as an answer for :func:`_address`
    or :func:`_ssh` to refuse."""
    if PLACEHOLDER_SHAPE.fullmatch(text) is None:
        return False
    if key == "receiver_address":
        return not (good_receiver_address(text) or has_scope_id(text))
    if key == "receiver_ssh":
        return not (good_receiver_ssh(text) or has_scope_id(text))
    return True


def _without_placeholders(value: str | list[str], key: str) -> str | list[str] | None:
    """An answer that is wholly a bracketed placeholder, as ``[don't know]``, is no answer."""
    if isinstance(value, str):
        return None if _is_placeholder(value, key) else value
    return [item for item in value if not _is_placeholder(item, key)]


def _parts(text: str, most: int, least: int, shape: str) -> list[str]:
    parts = [part.strip() for part in text.split("|")]
    if not least <= len(parts) <= most or not all(parts[:least]):
        raise ValueError(f"expected {shape}, separated by |")
    if any(PLACEHOLDER_SHAPE.fullmatch(part) for part in parts):
        raise ValueError("a part in brackets is a placeholder, not an answer; leave it out")
    return parts


def _contact(text: str) -> dict[str, str]:
    parts = _parts(text, 3, 1, "name, then optionally role and reach")
    return {key: part for key, part in zip(("name", "role", "reach"), parts, strict=False) if part}


def _tool(text: str) -> dict[str, Any]:
    name, mode = _parts(text, 2, 2, "name | writes or name | read-only")
    if mode.lower() not in _WRITES | _READS:
        raise ValueError("whether the tool writes is 'writes' or 'read-only'")
    return {"name": name, "writes": mode.lower() in _WRITES}


def _canary(text: str) -> dict[str, Any]:
    parts = _parts(text, 4, 3, "id | kind | where, and for kind file | path")
    identifier, kind, where = parts[:3]
    if not ENGAGEMENT_ID.fullmatch(identifier):
        raise ValueError("the id is not a name: 1-64 letters, digits, . _ -")
    if kind not in CANARY_KINDS:
        raise ValueError(f"the kind is one of {', '.join(CANARY_KINDS)}")
    canary: dict[str, Any] = {"id": identifier, "kind": kind, "where": where}
    if kind == "file":
        if len(parts) != 4 or not parts[3].startswith("/"):
            raise ValueError("a file canary names an absolute path as the fourth part")
        canary["path"] = parts[3]
    elif len(parts) == 4:
        raise ValueError(f"a canary of kind {kind} has no path; only a file does")
    canary["removed"] = None
    return canary


def _sentence(text: str) -> str:
    if PLACEHOLDER_SHAPE.fullmatch(text):
        raise ValueError("a placeholder in brackets is not an answer; leave it out")
    return text


def _known_value(text: str) -> str:
    if len(text) < MIN_KNOWN_VALUE:
        raise ValueError(f"shorter than {MIN_KNOWN_VALUE} characters")
    return text


def _env_name(text: str) -> str:
    if not ENV_NAME.fullmatch(text):
        raise ValueError("expected the name of an environment variable, not its value")
    return text


def _choice(allowed: tuple[str, ...]) -> Callable[[str], str]:
    def check(text: str) -> str:
        if text not in allowed:
            raise ValueError(f"expected one of {', '.join(allowed)}")
        return text

    return check


def _address(text: str) -> str:
    if not good_receiver_address(text):
        raise ValueError(
            "expected host or host:port, no scheme, path, query, fragment or user; an IPv6 "
            "address in square brackets; a port from 1 to 65535"
        )
    return text


def _ssh(text: str) -> str:
    if not good_receiver_ssh(text):
        raise ValueError(
            "expected a reference to the receiver's host, as [user@]host[:port] or <NAME>; "
            "never a key"
        )
    return text


def _prefix(text: str) -> str:
    if not good_receiver_prefix(text):
        raise ValueError("not a path prefix the receiver takes; see the question")
    return text


def _seconds(text: str) -> int:
    # Leading zeros do not count. The length next: int() refuses more than 4300 digits with a
    # fault of its own.
    digits = text.lstrip("0") if text.isascii() and text.isdigit() else ""
    if (
        not digits
        or len(digits) > len(str(MAX_RETENTION_SECONDS))
        or int(digits) > MAX_RETENTION_SECONDS
    ):
        raise ValueError(
            f"expected a whole number of seconds, from 1 to {MAX_RETENTION_SECONDS} (90 days)"
        )
    return int(digits)


#: What reads each answer, and so what refuses it. A message never repeats the answer: a known
#: value, a prefix and a variable named wrongly may each be the secret itself.
_READERS: dict[str, Callable[[str], Any]] = {
    "customer": _sentence,
    "agency": _sentence,
    "agency_contacts": _contact,
    "tools": _tool,
    "abort_criteria": _sentence,
    "emergency_name": _sentence,
    "emergency_reach": _sentence,
    "known_values": _known_value,
    "salt_env": _env_name,
    "canaries": _canary,
    "receiver_variant": _choice(RECEIVER_VARIANTS),
    "receiver_address": _address,
    "receiver_path_prefix": _prefix,
    "receiver_key_env": _env_name,
    "receiver_ssh": _ssh,
    "receiver_retention_seconds": _seconds,
    "token_passthrough": _choice(PASSTHROUGH_METHODS),
}
#: What makes two items of a list the same one: a tool's name, a canary's id.
_IDENTITY = {"tools": "name", "canaries": "id"}


def _check_fields(fields: dict[str, Any]) -> None:
    """Every answer to :data:`FIELD_ORDER` read the way :func:`draft` reads it, or
    :class:`_Invalid` with the place. Repeats no answer."""
    for key in FIELD_ORDER:
        if key not in fields:
            continue
        value = fields[key]
        if key not in LIST_FIELDS:
            if not isinstance(value, str):
                raise _Invalid(key, "expected one answer, but there is more than one")
            _read(key, value, key)
            continue
        if not isinstance(value, list):
            raise _Invalid(key, 'expected a list of strings, as ["first", "second"]')
        seen: set[Any] = set()
        for index, item in enumerate(value):
            read = _read(key, item, f"{key}[{index}]")
            identity = read[_IDENTITY[key]] if key in _IDENTITY else None
            if key == "known_values":
                identity = read
            if identity is not None and identity in seen:
                raise _Invalid(f"{key}[{index}]", "listed twice")
            seen.add(identity)


def _value(fields: dict[str, Any], key: str) -> Any:
    """The answer to a question that takes one, as the file takes it, or None."""
    return _read(key, fields[key], key) if key in fields else None


def _read(key: str, text: Any, where: str) -> Any:
    """One answer as the file takes it, or :class:`_Invalid` with the place."""
    if not isinstance(text, str) or not text.strip():
        raise _Invalid(where, "expected a string")
    try:
        return _READERS[key](text.strip())
    except ValueError as invalid:
        raise _Invalid(where, str(invalid)) from None


# -- the draft ---------------------------------------------------------------------------------


def draft(answers: Answers, *, engagement_id: str) -> tuple[str, list[str]]:
    """The draft engagement file as JSON text, and what is still missing from it.

    JSON, so the draft is written and read with nothing but the standard library. What the
    answers give is filled in — a target's host, port and path from each ``http`` or ``https``
    URL in a server's ``reached_how``, the path always listed, so an endpoint target is never
    "any path". What they cannot give is a bracketed placeholder where the file takes one
    (``end_customer.name``, ``reference``, ``contacts``, ``window``, ``retention.delete_after``,
    ``abort_criteria``, ``emergency``, ``salt_env``, the host of a server whose answers name no
    URL that comes apart cleanly), and the narrowest valid value where it does not (``actions``:
    ``list`` and ``call`` both false). The answers about the servers, the constraints and the
    notes go under ``declared`` unchanged; the answers to :data:`FIELD_ORDER` go into the fields
    of the second version. A receiver is written only when its answers say whether it is
    ``local`` or ``reachable``; of a reachable one, what is not answered is a placeholder. Each
    line of the list says where and what, for stderr; none repeats an answer.

    The text is read back before it is returned: it loads as an engagement file, and its
    placeholders are the ones the list names. Raises :class:`IntakeError` for an id that is not
    a name or holds a known value, and for an answer to :data:`FIELD_ORDER` that the file would
    not take, with its place.
    """
    if not isinstance(engagement_id, str) or not ENGAGEMENT_ID.fullmatch(engagement_id):
        raise IntakeError("the engagement id is not a name: 1-64 letters, digits, . _ -")
    if answers.refused:
        number, field = answers.refused[0]
        more = len(answers.refused) - 1
        kinds = answers.refused_categories[0] if answers.refused_categories else ()
        named = ", ".join(f"{_CATEGORY_WORDS.get(code, code)} ({code})" for code in kinds)
        if kinds == _BELOW_SECRET:
            raise IntakeError(
                f"line {number} ({field}): directly follows a line of a field that may hold a "
                "secret and may be the rest of its value; it is refused and kept nowhere. A value "
                "goes on the field's own line; leave a blank line before a line that is meant to "
                "be kept" + (f" ({more} more the same)" if more else ""),
                source=answers.source,
            )
        if not kinds:
            raise IntakeError(
                f"line {number} ({field}): begins like the label of a field that may hold a "
                "secret, but is not written as one; write exactly "
                f"'{_LABELS[field]}: <value>', one line for each value, or delete the line"
                + (f" ({more} more the same)" if more else ""),
                source=answers.source,
            )
        raise IntakeError(
            f"line {number}{f' ({field})' if field else ''}: holds a character of the "
            f"{'category' if len(kinds) == 1 else 'categories'} {named}, which is not allowed; "
            "the line is refused and kept nowhere" + (f" ({more} more the same)" if more else ""),
            source=answers.source,
        )
    try:
        _check_fields(answers.fields)
    except _Invalid as invalid:
        raise IntakeError(f"{invalid.where}: {invalid.message}", source=answers.source) from None
    # The id is written as it is, so it may hold no known value: a name is refused, not replaced.
    # Said as the file says it, by index, never with the value.
    for index, value in enumerate(answers.fields.get("known_values", [])):
        if _read("known_values", value, "") in engagement_id:
            raise IntakeError(
                f"id: holds known_values[{index}]; choose an id that names no customer value",
                source=answers.source,
            )
    data = answers.data
    fields = answers.fields
    servers = data.get("servers", [])
    constraints = data.get("constraints", {})
    missing: list[str] = []
    placeholders: list[str] = []

    def placeholder(where: str, value: str, words: str) -> str:
        placeholders.append(where)
        missing.append(f"{where}: {words}")
        return value

    hours = (
        "; the customer's hours are under declared.constraints.hours"
        if "hours" in constraints
        else ""
    )
    document: dict[str, Any] = {
        "version": FORMAT_VERSION_2,
        "id": engagement_id,
        "end_customer": {
            "name": _value(fields, "customer")
            or placeholder("end_customer.name", "[END CUSTOMER NAME]", "the end customer's name")
        },
    }
    if "agency" in fields or "agency_contacts" in fields:
        agency: dict[str, Any] = {
            "name": _value(fields, "agency")
            or placeholder("agency.name", "[AGENCY NAME]", "the agency's name")
        }
        if "agency_contacts" in fields:
            agency["contacts"] = [
                _read("agency_contacts", c, "") for c in fields["agency_contacts"]
            ]
        document["agency"] = agency
    document |= {
        "reference": placeholder(
            "reference",
            "[DOCUMENT ID OR FILE NAME OF THE SIGNED ENGAGEMENT]",
            "the signed engagement this file is the scope of",
        ),
        "contacts": [
            {
                "name": placeholder("contacts[0].name", "[NAME]", "who is reachable during runs"),
                "role": placeholder("contacts[0].role", "[ROLE]", "their role"),
                "reach": placeholder(
                    "contacts[0].reach",
                    "[HOW TO REACH THEM DURING THE WINDOW]",
                    "how to reach them during the window",
                ),
            }
        ],
        "window": {
            "from": placeholder(
                "window.from",
                "[WINDOW OPENS, UTC, AS 2026-11-02T08:00:00Z]",
                "when runs may begin, in UTC; a window is not read from words" + hours,
            ),
            "until": placeholder(
                "window.until",
                "[WINDOW CLOSES, UTC, AS 2026-11-06T18:00:00Z]",
                "when runs must have ended, in UTC",
            ),
        },
    }
    targets = _targets(servers, placeholder, missing)
    document["targets"] = targets
    document["actions"] = {"list": False, "call": False}
    _second(document, fields, placeholder, missing)
    missing.append(
        "actions: list and call are both false, the narrowest; say what the engagement permits "
        "(drive lists what the server offers, so it needs list: true)"
    )
    missing.append("scenarios: none listed; list each scenario file the runs use, with its SHA-256")
    if "rate" in constraints:
        missing.append(
            "pacing: not set; the customer's rate is under declared.constraints.rate, and a pace "
            "is not read from words"
        )
    document["retention"] = {
        "delete_after": placeholder(
            "retention.delete_after",
            "[DELETE AFTER, AS 2027-01-31]",
            "the day after which the engagement's data is deleted",
        )
    }
    document["declared"] = copy.deepcopy(data)
    for index, server in enumerate(servers):
        missing.append(
            f"declared.servers[{index}].entry: the manifest entry that is "
            f"{_server(server, index)}, for the operator to add; without it the report lists the "
            "declaration unpaired"
        )
    if answers.unplaced:
        numbers = ", ".join(str(number) for number in answers.unplaced)
        many = len(answers.unplaced) > 1
        missing.append(
            f"declared.notes: {'lines' if many else 'line'} {numbers} of the answers "
            f"{'fit' if many else 'fits'} no question and {'are' if many else 'is'} kept there "
            f"as written; read {'them' if many else 'it'}"
        )
    text = json.dumps(document, ensure_ascii=True, indent=2) + "\n"
    _read_back(text, placeholders, answers.source)
    return text, missing


def _second(
    document: dict[str, Any],
    fields: dict[str, Any],
    placeholder: Callable[[str, str, str], str],
    missing: list[str],
) -> None:
    """The fields only the second version has, added to the draft in the order of the file. What
    the answers give is written as read; what a required field lacks is a placeholder."""
    if "tools" in fields:
        document["tools"] = [_read("tools", t, "") for t in fields["tools"]]
    document["abort_criteria"] = [
        _read("abort_criteria", a, "") for a in fields.get("abort_criteria", [])
    ] or [
        placeholder(
            "abort_criteria[0]", "[WHEN TO STOP AT ONCE]", "when the test must stop, as a sentence"
        )
    ]
    document["emergency"] = {
        "name": _value(fields, "emergency_name")
        or placeholder("emergency.name", "[EMERGENCY CONTACT]", "whom to call if something fails"),
        "reach": _value(fields, "emergency_reach")
        or placeholder(
            "emergency.reach", "[HOW TO REACH THEM]", "how to reach the emergency contact"
        ),
    }
    if "known_values" in fields:
        document["known_values"] = [_read("known_values", v, "") for v in fields["known_values"]]
    document["salt_env"] = _value(fields, "salt_env") or placeholder(
        "salt_env",
        "[NAME OF THE ENVIRONMENT VARIABLE THAT HOLDS THE SALT]",
        "the name of the environment variable that holds the salt",
    )
    if "canaries" in fields:
        document["canaries"] = [_read("canaries", c, "") for c in fields["canaries"]]
    receiver = _receiver(fields, placeholder, missing)
    if receiver is not None:
        document["receiver"] = receiver
    if "token_passthrough" in fields:
        document["token_passthrough"] = {"method": _value(fields, "token_passthrough")}


def _receiver(
    fields: dict[str, Any], placeholder: Callable[[str, str, str], str], missing: list[str]
) -> dict[str, Any] | None:
    """The receiver block, or None when no answer is about a receiver, or when none says which
    variant it is: that is not guessed, and the missing list says so."""
    asked = [key for key in FIELD_ORDER if key.startswith("receiver_") and key in fields]
    if not asked:
        return None
    if "receiver_variant" not in fields:
        missing.append(
            f"receiver: {', '.join(asked)} answered, but not whether the receiver is local or "
            "reachable, so no receiver is written; answer receiver_variant"
        )
        return None
    reachable = fields["receiver_variant"].strip() == "reachable"
    receiver: dict[str, Any] = {"variant": fields["receiver_variant"].strip()}
    asks = {
        "address": ("[RECEIVER ADDRESS, AS HOST OR HOST:PORT]", "where the receiver is reached"),
        "path_prefix": ("[RECEIVER PATH PREFIX]", "the secret path prefix of the receiver"),
        "key_env": (
            "[NAME OF THE VARIABLE THAT HOLDS THE RECEIVER KEY]",
            "the name of the environment variable that holds the receiver's key",
        ),
        "ssh": None,
        "retention_seconds": (
            "[SECONDS THE RECEIVER KEEPS WHAT IT RECEIVES]",
            "how long the receiver keeps what it receives",
        ),
    }
    for key, ask in asks.items():
        answer = fields.get(f"receiver_{key}")
        if answer is not None:
            receiver[key] = _read(f"receiver_{key}", answer, "")
        elif reachable and ask is not None:
            receiver[key] = placeholder(f"receiver.{key}", *ask)
    return receiver


def _targets(servers: list[dict[str, Any]], placeholder: Any, missing: list[str]) -> list[dict]:
    """One target for each host and port read off a URL in the answers, with every path the
    URLs name on it; a placeholder host for each server whose answers give none."""
    targets: list[dict[str, Any]] = []
    by_place: dict[tuple[str, int], dict[str, Any]] = {}
    for index, server in enumerate(servers):
        reached = server.get("reached_how")
        said = [reached] if isinstance(reached, str) else list(reached or [])
        urls = [url for text in said for url in _urls(text)]
        found = 0
        for url in urls:
            read = _read_url(url)
            if read is None:
                continue
            host, port, path, _scheme = read
            target = by_place.get((host, port))
            if target is None:
                target = {"host": host, "ports": [port], "paths": []}
                by_place[(host, port)] = target
                targets.append(target)
            k = targets.index(target)
            if path == "":
                path = "/"
                missing.append(
                    f"targets[{k}].paths: '/' is listed for {_server(server, index)}, whose URL "
                    "names no path; paths are compared exactly, so the run's URL must end in /"
                )
            if path not in target["paths"]:
                target["paths"].append(path)
            # The run's own rule, not a second reading of loopback: plain HTTP to
            # anything but 127.0.0.1 or [::1] is refused before anything connects.
            if plain_http_refusal(url) is not None:
                missing.append(
                    f"targets[{k}]: {_server(server, index)} is reached over plain HTTP to "
                    f"{host}, and a run to it would be refused: plain HTTP is spoken only to "
                    "127.0.0.1 or [::1]; the server's https:// URL is needed"
                )
            found += 1
        if not found:
            why = (
                "its answers name no http or https URL that can be taken apart into host, port "
                "and path"
                if reached
                else "it does not say how it is reached"
            )
            targets.append(
                {
                    "host": placeholder(
                        f"targets[{len(targets)}].host",
                        f"[HOST OF SERVER {index + 1}]",
                        f"where {_server(server, index)} is reached; {why}",
                    )
                }
            )
    if not targets:
        targets.append(
            {
                "host": placeholder(
                    "targets[0].host", "[TARGET HOST]", "no server is declared in the answers"
                )
            }
        )
    return targets


def _urls(text: str) -> list[str]:
    """The words of an answer that look like a URL, without the punctuation around them. Only
    from an answer with nothing unprintable in it: a URL read off a line that hides characters
    could name a host the reader of the draft does not see."""
    if not _printable(text):
        return []
    found = []
    for word in text.split():
        word = word.strip("<>()\"'.,;")
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[!-~]+", word):
            found.append(word)
    return found


def _read_url(url: str) -> tuple[str, int, str, str] | None:
    """Host as a target names it, port, path (``""``: none given) and scheme — taken apart as
    the gate takes ``--http`` apart — or None for a URL that does not come apart so, or whose
    path the file could not list."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        userinfo = parts.username is not None or parts.password is not None
    except ValueError:
        return None
    if scheme not in DEFAULT_PORTS or userinfo or not parts.netloc:
        return None
    split = split_target(parts.netloc)
    if split is None:
        return None
    name, port = split
    host = f"[{name}]" if ":" in name else name
    path = parts.path
    if path and not TARGET_PATH.fullmatch(path):
        return None
    return host, DEFAULT_PORTS[scheme] if port is None else port, path, scheme


def _server(server: dict[str, Any], index: int) -> str:
    """A server as the missing list names it: by its place, and by its name when it has one,
    without the characters that have no business on a terminal."""
    name = server.get("name")
    if isinstance(name, str):
        return f"declared.servers[{index}] ({safe_text(name)!r})"
    return f"declared.servers[{index}]"


def _read_back(text: str, placeholders: list[str], answers_source: str) -> None:
    """The draft as :func:`engagement.load` would read it: a file that would be refused, or
    whose placeholders are not the ones listed, is a fault here and is never handed out —
    :class:`IntakeError`, with words, rather than a traceback."""
    try:
        # A draft lists no scenario file, so the directory they would be resolved in is never
        # looked at.
        loaded = engagement.loads(
            text.encode("utf-8"), source="the draft", directory=Path("."), suffix=".json"
        )
    except EngagementError as refused:
        raise IntakeError(
            f"the draft made from {safe_text(answers_source)} does not read back as an "
            f"engagement file ({refused.reason}), so it is not written; this is a fault in "
            "intake, not in the answers"
        ) from None
    if sorted(loaded.placeholders) != sorted(placeholders):
        raise IntakeError(
            f"the draft made from {safe_text(answers_source)} holds placeholders at "
            f"{', '.join(loaded.placeholders)}, not at the ones listed as missing "
            f"({', '.join(placeholders)}), so it is not written; this is a fault in intake, not "
            "in the answers"
        )
