"""The check of an exported tree: nothing private goes out under ``results/``.

Before the export hands over the tree it wrote, :func:`check_tree` reads all of it: every file
(text, JSON, YAML, the companions and the network reports alike) and every file and directory
name. Each rule is a function of its own and names itself in :attr:`Problem.rule`; any problem
means the export is refused. A problem says where and what kind of thing was found, never the
thing: not the secret, not the id, not a part of either.

The rules:

Every text rule reads the same forms of a text (:data:`FORMS`): the text, its compatibility form
(NFKC: full-width letters …), the text with ``%XX`` decoded, and that in NFKC. A hint names the
form a find is in, never the thing.

- ``canary_id``: the id of a real run's canary, in any case; its normal form (letters and digits
  alone, as ``bench._normalised``); its 8 hex characters alone. Each in every form, and read
  backwards. The placeholder ``MCPB-CANARY-<SERVER>-xxxxxxxx`` is not the id.
- ``hmac_key``: a key as hex (any case), base64 and base64url (the forms without ``=``, which
  the padded forms contain), in every form; and raw, in the bytes of the file. A key cut out of
  a longer base64 run at another alignment is not found.
- ``env_value``: a value of ``launch.env`` of :data:`MIN_SECRET_VALUE` characters or more, in
  any case, in every form.
- ``secret``: a secret known only by its length and SHA-256: every window of that many bytes of
  the file and of the UTF-8 of each other form is hashed, one hash per window and length. The
  length is that of the secret in UTF-8; for the runner's passwords (``token_urlsafe``) that is
  the number of characters.
- ``host_path``: a path of this machine (the repository, the home, the private place, the
  temporary directory), in any case.
- ``home``: any ``/home/<name>``, ``/Users/<name>``, ``/root/``, ``~/`` or drive path (``C:\\``).
  A path inside a container (``/srv/fixtures``, ``/tmp`` as the container's tmpfs, the paths
  of a Dockerfile) is not a path of this machine and is allowed; a host path given that is also
  one (a temporary directory that is ``/tmp`` itself) makes it a find all the same.
- ``private_dir``: ``.notes`` or ``.harness``, in any case.
- ``dropped_server``: a mark of a dropped server (its package, its image tag, its source
  repository where no server that stays has it) anywhere, in any case. Its bare name only where
  it names a server, as a whole and in any case: a part of a path in the tree
  (``results/git/…``), a string of a JSON document (``"server": "git"``), a cell of a Markdown
  table (``| git |``), the text of an HTML element (``<td>git</td>``), the value of a YAML line
  (``name: git``, ``- git``). A short name is also a word: ``git`` in prose, in
  ``.github/FUNDING.yml`` or in ``github-http`` is no find.
- ``unreleased_finding``: a signal of a ``result.json`` (``result_version`` 1) whose
  ``(server, stage, signal, path)`` is not among the released findings; a ``result.json`` that
  cannot be read as one is ``unreadable_result``.
- ``symlink``: a symbolic link in the tree; it is not followed. ``special_file`` is anything
  else that is neither a file nor a directory, ``unreadable`` a file or directory that cannot be
  read: neither is let through as having nothing in it.

All text rules are applied to the names as well. A file that is not UTF-8 is read as Latin-1
for them. Every rule reads the text with fixed strings or patterns that cannot start a long run
at each position, so the time is linear in the size of the tree (times the number of things
looked for). Standard library only; no Docker, no network.

A file that parses as JSON, whatever its name, is read as a document as well: every string in
it, each value and each key, goes through the text rules (but ``unreleased_finding``) as a text
of its own, so a JSON escape (``\\"``, ``\\\\``, ``\\/``, ``\\uXXXX``) hides nothing the raw text
would show. A hit there has its JSON path as ``where`` (``signals[0].excerpt``; ``(key)`` after
it for the key of that member). A key is named in the path only if it is a plain name and
nothing is found in it, else by its place among the members (``{2}``), and a path in which a rule
finds something is given by places alone: the path never shows the thing either. A rule that
already found something in the raw text of the file adds nothing from the document; the file is
refused all the same. A document nested too deeply to be parsed is ``unreadable``, not a file
without strings. Numbers are no text.

What the rules do not find:

- an id that a server cuts on purpose into pieces of fewer than 8 hex characters spread over
  two values, with other text between them;
- the base64 of a secret, an id or a value of ``launch.env``, and their bytes written as hex
  (``4d435042…`` for ``MCPB…``; the 8 hex characters an id ends in are found, as above).
"""

from __future__ import annotations

import base64
import bisect
import hashlib
import html
import json
import os
import re
import stat
import unicodedata
from collections.abc import Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, unquote_to_bytes

#: The shortest value of ``launch.env`` that is looked for (as ``bench.MIN_SECRET_VALUE``).
MIN_SECRET_VALUE = 4
#: The hex characters at the end of a canary's id (as ``bench.CANARY_HEX``).
CANARY_HEX = 8
RESULT_FILE = "result.json"
RESULT_VERSION = 1
PRIVATE_DIRS = (".notes", ".harness")
#: Where a problem is not at a place in the text: in the name of the file or directory.
WHERE_NAME = "name"
#: The forms of a text every text rule reads, each made once per text.
FORMS = ("text", "nfkc", "percent", "percent, nfkc")

_NOT_ALNUM = re.compile(r"[^a-z0-9]")
_HEX = re.compile(r"[0-9a-f]+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
#: One character of the name after the directory is enough: no run of it is read.
_HOME = re.compile(r"/home/[^/\s]|/Users/[^/\s]|/root/|~/|(?<![A-Za-z0-9])[A-Za-z]:\\")


@dataclass(frozen=True)
class Forbidden:
    """What must not be in the exported tree. A value that cannot be looked for (an empty key,
    a canary id without its hex part, the path ``/``) is refused here, not skipped."""

    canary_ids: Sequence[str] = ()
    hmac_keys: Sequence[bytes] = ()
    #: The values of ``launch.env`` of all definitions; the shorter ones are not looked for.
    env_values: Sequence[str] = ()
    #: ``(length, sha256 hex)`` of each secret of a run (the helpers' passwords).
    secret_digests: Sequence[tuple[int, str]] = ()
    host_paths: Sequence[str | os.PathLike[str]] = ()
    #: For each dropped server, by its name, the marks it is known by besides (package, image
    #: tag, source). A mark is looked for anywhere; the name only where it names a server.
    dropped: Mapping[str, Sequence[str]] = field(default_factory=dict)
    #: The released findings, as ``(server, stage, signal, path)``.
    released: Collection[tuple[Any, Any, Any, Any]] = ()

    def __post_init__(self) -> None:
        for canary_id in self.canary_ids:
            if (
                not isinstance(canary_id, str)
                or len(canary_id) <= CANARY_HEX
                or not _HEX.fullmatch(canary_id[-CANARY_HEX:].lower())
            ):
                raise ValueError("a canary id must end in its 8 hex characters")
        for key in self.hmac_keys:
            if not isinstance(key, bytes) or not key:
                raise ValueError("an HMAC key must be bytes, and not empty")
        for value in self.env_values:
            if not isinstance(value, str):
                raise ValueError("a value of launch.env must be a string")
        for item in self.secret_digests:
            length, digest = item
            if (
                not isinstance(length, int)
                or isinstance(length, bool)
                or length < 1
                or not isinstance(digest, str)
                or not _SHA256.fullmatch(digest.lower())
            ):
                raise ValueError("a secret is (length of 1 or more, SHA-256 in hex)")
        for path in self.host_paths:
            if not os.fspath(path).rstrip("/\\"):
                raise ValueError("a host path must not be empty or the root")
        for name, marks in self.dropped.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("the name of a dropped server must be a non-empty string")
            if isinstance(marks, str) or not all(isinstance(m, str) and m for m in marks):
                raise ValueError("the marks of a dropped server must be non-empty strings")
        for finding in self.released:
            if not isinstance(finding, tuple) or len(finding) != 4:
                raise ValueError("a released finding is (server, stage, signal, path)")


@dataclass(frozen=True)
class Problem:
    """One find. ``file`` is relative to the root, with ``/``; ``where`` is ``line N``,
    ``byte N``, :data:`WHERE_NAME`, ``signals[N]``, the JSON path of a string or empty (the file
    as a whole, or the string that is the whole document); ``hint`` says what kind of thing is
    there and never the thing."""

    file: str
    rule: str
    where: str
    hint: str


#: A hit before it has a file: (rule, where, hint).
_Hit = tuple[str, str, str]


class _Text:
    """The text of a file or name, with its forms made once and only when asked for."""

    def __init__(self, text: str, data: bytes, positional: bool) -> None:
        self.text = text
        self.data = data
        #: False for a name: every hit is in the name, not at a line.
        self.positional = positional
        self._forms: dict[str, str] = {}

    def form(self, name: str) -> str:
        if name not in self._forms:
            if name == "text":
                made = self.text
            elif name == "nfkc":
                made = unicodedata.normalize("NFKC", self.text)
            elif name == "percent":
                made = unquote(self.text)
            elif name == "percent, nfkc":
                made = unicodedata.normalize("NFKC", self.form("percent"))
            else:
                raise ValueError(f"no form {name}")
            self._forms[name] = made
        return self._forms[name]

    def forms(self, names: Sequence[str]) -> Iterator[tuple[str, str]]:
        """The forms in ``names`` that differ from those before them: a form that is the text
        again has nothing new to find."""
        seen: list[str] = []
        for name in names:
            made = self.form(name)
            if any(made == other for other in seen):
                continue
            seen.append(made)
            yield name, made

    def where(self, form: str, positions: Sequence[int]) -> list[str]:
        """``line N`` in ``form`` for each position, in one pass over it."""
        if not self.positional:
            return [WHERE_NAME] * len(positions)
        order = sorted(range(len(positions)), key=lambda i: positions[i])
        out = [""] * len(positions)
        line, at = 1, 0
        for index in order:
            line += form.count("\n", at, positions[index])
            at = positions[index]
            out[index] = f"line {line}"
        return out


def _find_all(haystack: str, needle: str) -> Iterator[int]:
    at = haystack.find(needle)
    while at != -1:
        yield at
        at = haystack.find(needle, at + 1)


def _in_form(what: str, form_name: str) -> str:
    """The hint ``what``, with the form it was found in unless that is the text."""
    return what if form_name == "text" else f"{what} ({form_name})"


def _hits(
    text: _Text, form_name: str, form: str, needles: Sequence[tuple[str, str]], rule: str
) -> list[_Hit]:
    """Every place of each needle in ``form``: ``needles`` are ``(needle, what)``."""
    positions: list[int] = []
    hints: list[str] = []
    for needle, what in needles:
        for at in _find_all(form, needle):
            positions.append(at)
            hints.append(_in_form(what, form_name))
    return [(rule, w, h) for w, h in zip(text.where(form, positions), hints, strict=True)]


def _normal_form(form: str) -> tuple[str, list[int]]:
    """The letters and digits of ``form`` in lower case, and where each line starts in them."""
    starts: list[int] = []
    parts: list[str] = []
    length = 0
    for line in form.split("\n"):
        starts.append(length)
        part = _NOT_ALNUM.sub("", line.lower())
        parts.append(part)
        length += len(part)
    return "".join(parts), starts


def rule_canary_id(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    found: list[_Hit] = []
    if not forbidden.canary_ids:
        return found
    for form_name, form in text.forms(FORMS):
        lowered = form.lower()
        needles: list[tuple[str, str]] = []
        normal: list[tuple[str, str]] = []
        for canary_id in forbidden.canary_ids:
            whole, hex_part = canary_id.lower(), canary_id[-CANARY_HEX:].lower()
            wanted = _NOT_ALNUM.sub("", whole)
            needles += [
                (whole, "the id of a real run's canary"),
                (whole[::-1], "the id of a real run's canary, read backwards"),
                (hex_part, "the hex part of a real run's canary id"),
                (hex_part[::-1], "the hex part of a real run's canary id, read backwards"),
            ]
            normal += [
                (wanted, "the id of a real run's canary in its normal form"),
                (wanted[::-1], "the id of a real run's canary in its normal form, read backwards"),
            ]
        found += _hits(text, form_name, lowered, needles, "canary_id")
        flat, starts = _normal_form(form)
        for needle, what in normal:
            for at in _find_all(flat, needle):
                line = bisect.bisect_right(starts, at)
                where = f"line {line}" if text.positional else WHERE_NAME
                hint = what if form_name == "text" else f"{what} ({form_name})"
                found.append(("canary_id", where, hint))
    return found


def rule_hmac_key(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    found: list[_Hit] = []
    if not forbidden.hmac_keys:
        return found
    hex_needles: list[tuple[str, str]] = []
    base64_needles: list[tuple[str, str]] = []
    for key in forbidden.hmac_keys:
        hex_needles.append((key.hex(), "an HMAC key in hex"))
        # The forms without ``=`` are in the padded ones: one search finds both.
        base64_needles.append(
            (base64.b64encode(key).decode("ascii").rstrip("="), "an HMAC key in base64")
        )
        base64_needles.append(
            (base64.urlsafe_b64encode(key).decode("ascii").rstrip("="), "an HMAC key in base64url")
        )
        at = text.data.find(key)
        while at != -1:
            found.append(
                ("hmac_key", f"byte {at}" if text.positional else WHERE_NAME, "an HMAC key, raw")
            )
            at = text.data.find(key, at + 1)
    for form_name, form in text.forms(FORMS):
        found += _hits(text, form_name, form.lower(), hex_needles, "hmac_key")
        found += _hits(text, form_name, form, base64_needles, "hmac_key")
    return found


def rule_env_value(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    values = sorted({v.lower() for v in forbidden.env_values if len(v) >= MIN_SECRET_VALUE})
    found: list[_Hit] = []
    if not values:
        return found
    needles = [(value, "a value of launch.env") for value in values]
    for form_name, form in text.forms(FORMS):
        found += _hits(text, form_name, form.lower(), needles, "env_value")
    return found


def rule_secret(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    by_length: dict[int, set[bytes]] = {}
    for length, digest in forbidden.secret_digests:
        by_length.setdefault(length, set()).add(bytes.fromhex(digest))
    found: list[_Hit] = []
    if not by_length:
        return found
    # The bytes of the file, then the UTF-8 of each form of its text that differs from those
    # before it. ``%XX`` is decoded to bytes, which need not be UTF-8.
    forms = [("bytes", text.data)]
    for form_name, _ in text.forms(FORMS):
        if form_name == "text":
            continue
        if form_name == "percent":
            data = unquote_to_bytes(text.text)
        else:
            data = text.form(form_name).encode("utf-8", "surrogatepass")
        if not any(data == other for _, other in forms):
            forms.append((form_name, data))
    sha256 = hashlib.sha256
    for form_name, data in forms:
        view = memoryview(data)
        positions: list[int] = []
        for length, digests in by_length.items():
            for at in range(len(data) - length + 1):
                if sha256(view[at : at + length]).digest() in digests:
                    positions.append(at)
        what = "a secret of a run" if form_name == "bytes" else f"a secret of a run ({form_name})"
        for at in positions:
            where = f"byte {at}" if text.positional else WHERE_NAME
            found.append(("secret", where, what))
    return found


def rule_host_path(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    paths = sorted({os.fspath(p).rstrip("/\\").lower() for p in forbidden.host_paths})
    if not paths:
        return []
    needles = [(path, "a path of this machine") for path in paths]
    found: list[_Hit] = []
    for form_name, form in text.forms(FORMS):
        found += _hits(text, form_name, form.lower(), needles, "host_path")
    return found


def rule_home(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    found: list[_Hit] = []
    for form_name, form in text.forms(FORMS):
        positions = [match.start() for match in _HOME.finditer(form)]
        hint = _in_form("a home directory or drive path", form_name)
        found += [("home", where, hint) for where in text.where(form, positions)]
    return found


def rule_private_dir(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    needles = [(name, "a private directory") for name in PRIVATE_DIRS]
    found: list[_Hit] = []
    for form_name, form in text.forms(FORMS):
        found += _hits(text, form_name, form.lower(), needles, "private_dir")
    return found


#: The text of an HTML element between its tags: it starts at ``>`` only and its run ends at the
#: next ``<`` or ``>``, so no two runs overlap.
_ELEMENT_TEXT = re.compile(r">([^<>]*)<")
_YAML_QUOTES = ('"', "'")


def _is_name(value: str, names: Collection[str]) -> bool:
    return value.strip().lower() in names


def _yaml_value(line: str) -> str | None:
    """The whole value of a YAML line ``key: value`` or ``- value`` (also ``- key: value``),
    without a comment after it and without its quotes; ``None`` for any other line."""
    at, end = 0, len(line)
    while at < end and line[at] in " \t":
        at += 1
    listed = False
    while at < end and line[at] == "-" and (at + 1 == end or line[at + 1] in " \t"):
        listed = True
        at += 1
        while at < end and line[at] in " \t":
            at += 1
    rest = line[at:]
    colon = rest.find(": ")
    if colon != -1:
        rest = rest[colon + 2 :]
    elif not listed:
        return None
    comment = rest.find(" #")
    if comment != -1:
        rest = rest[:comment]
    rest = rest.strip()
    if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in _YAML_QUOTES:
        rest = rest[1:-1]
    return rest


def _name_positions(text: str, names: Collection[str]) -> list[int]:
    """Where one of ``names`` (in lower case) stands as a whole and so names a server: the whole
    text (a name in the tree, a string of a JSON document), a cell of a Markdown table, the text
    of an HTML element, the value of a YAML line. Each in any case and without the white space
    around it."""
    positions: list[int] = []
    if _is_name(text, names):
        positions.append(len(text) - len(text.lstrip()))
    for match in _ELEMENT_TEXT.finditer(text):
        if _is_name(html.unescape(match.group(1)), names):
            positions.append(match.start(1))
    start = 0
    for line in text.split("\n"):
        if "|" in line:
            at = start
            for cell in line.split("|"):
                if _is_name(cell, names):
                    positions.append(at)
                at += len(cell) + 1
        value = _yaml_value(line)
        if value is not None and _is_name(value, names):
            positions.append(start)
        start += len(line) + 1
    return positions


def rule_dropped_server(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    """A mark of a dropped server (package, image tag, source) anywhere, in any case; its bare
    name only where it names a server (:func:`_name_positions`): a short name such as ``git`` or
    ``fetch`` is also a word, and in a path such as ``.github/`` it is none."""
    marks = sorted({m.lower() for marks in forbidden.dropped.values() for m in marks})
    names = {name.lower() for name in forbidden.dropped}
    found: list[_Hit] = []
    if not marks and not names:
        return found
    needles = [(mark, "a mark of a dropped server") for mark in marks]
    for form_name, form in text.forms(FORMS):
        found += _hits(text, form_name, form.lower(), needles, "dropped_server")
        if names:
            hint = _in_form("the name of a dropped server", form_name)
            positions = _name_positions(form, names)
            found += [("dropped_server", where, hint) for where in text.where(form, positions)]
    return found


RULES = (
    rule_canary_id,
    rule_hmac_key,
    rule_env_value,
    rule_secret,
    rule_host_path,
    rule_home,
    rule_private_dir,
    rule_dropped_server,
)


def rule_unreleased_finding(data: bytes, forbidden: Forbidden) -> list[_Hit]:
    """The signals of a ``result.json`` that are not released; one that is not a result of
    version 1 is ``unreadable_result``, never a result without signals."""
    unreadable = [("unreadable_result", "", "not a result.json of result_version 1")]
    try:
        result = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        return unreadable
    if (
        not isinstance(result, dict)
        or result.get("result_version") != RESULT_VERSION
        or isinstance(result.get("result_version"), bool)
        or not isinstance(result.get("server"), str)
        or not isinstance(result.get("stage"), str)
        or not isinstance(result.get("signals"), list)
    ):
        return unreadable
    released = set(forbidden.released)
    found: list[_Hit] = []
    for index, signal in enumerate(result["signals"]):
        if not isinstance(signal, dict) or "signal" not in signal or "path" not in signal:
            return unreadable
        finding = (result["server"], result["stage"], signal["signal"], signal["path"])
        try:
            is_released = finding in released
        except TypeError:  # a list or an object where a string belongs
            return unreadable
        if not is_released:
            found.append(
                ("unreleased_finding", f"signals[{index}]", "a finding that is not released")
            )
    return found


def _check_text(text: _Text, forbidden: Forbidden) -> list[_Hit]:
    found: list[_Hit] = []
    for rule in RULES:
        found += rule(text, forbidden)
    return found


#: A key that may stand in a JSON path by its name.
_KEY_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_TOO_DEEP: _Hit = ("unreadable", "", "nested too deeply to be read as JSON")


class _Members(list):
    """The members of a JSON object as ``(key, value)`` pairs in the order of the file: a key
    that is there twice is kept twice, not only its last value."""


def _no_number(text: str) -> int:
    """A JSON number is no text. It is not made an int, which refuses a long one: the file would
    not parse, and its strings would go unread."""
    return 0


#: A place in a JSON document: (the place it is in, the step by name, the step by place).
_Path = tuple[Any, str, str] | None


def _where(path: _Path, suffix: str, forbidden: Forbidden) -> str:
    """``path`` as ``signals[0].excerpt``; by places alone if a rule finds something in that."""
    named: list[str] = []
    placed: list[str] = []
    while path is not None:
        path, by_name, by_place = path
        named.append(by_name)
        placed.append(by_place)
    shown = "".join(reversed(named)).lstrip(".")
    if _check_text(_Text(shown, shown.encode("utf-8"), False), forbidden):
        shown = "".join(reversed(placed))
    return shown + suffix


def _document_hits(data: bytes, forbidden: Forbidden, already: Collection[str]) -> list[_Hit]:
    """The hits of the text rules in each string (value or key) of ``data`` read as JSON, but
    those of a rule in ``already``. Nothing if ``data`` is no JSON; :data:`_TOO_DEEP` if it is
    nested too deeply to tell."""
    try:
        document = json.loads(data, object_pairs_hook=_Members, parse_int=_no_number)
    except RecursionError:
        return [_TOO_DEEP]
    except ValueError:
        return []
    cache: dict[str, list[tuple[str, str]]] = {}

    def hits_of(value: str) -> list[tuple[str, str]]:
        if value not in cache:
            # A lone surrogate (``\ud800``) is valid JSON. It is in the bytes as it was written
            # and U+FFFD in the text, which no rule's needle has: the rules encode the text.
            data = value.encode("utf-8", "surrogatepass")
            text = _Text(data.decode("utf-8", "replace"), data, False)
            hits = _check_text(text, forbidden)
            cache[value] = [(rule, hint) for rule, _, hint in hits if rule not in already]
        return cache[value]

    found: list[_Hit] = []
    # Without recursion, and a path is built into a string only for a hit: the time stays
    # linear in the size of the document whatever its depth.
    stack: list[tuple[Any, _Path]] = [(document, None)]
    while stack:
        node, path = stack.pop()
        if isinstance(node, str):
            found += [(rule, _where(path, "", forbidden), hint) for rule, hint in hits_of(node)]
        elif isinstance(node, _Members):
            later: list[tuple[Any, _Path]] = []
            for index, (key, value) in enumerate(node):
                place = f"{{{index}}}"
                plain = _KEY_NAME.fullmatch(key) is not None and not hits_of(key)
                member = (path, f".{key}" if plain else place, place)
                found += [
                    (rule, _where(member, " (key)", forbidden), hint) for rule, hint in hits_of(key)
                ]
                later.append((value, member))
            stack.extend(reversed(later))
        elif isinstance(node, list):
            stack.extend(
                (value, (path, f"[{index}]", f"[{index}]"))
                for index, value in reversed(list(enumerate(node)))
            )
    return found


def _text(data: bytes, positional: bool) -> _Text:
    """``data`` as text: UTF-8, or else Latin-1, which reads any bytes."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return _Text(text, data, positional)


def _walk(root: Path, relative: str) -> Iterator[tuple[str, os.DirEntry[str] | None, str]]:
    """``(relative path, entry, error)`` for everything under ``root``, sorted, without
    following a link."""
    try:
        with os.scandir(root / relative if relative else root) as listing:
            entries = sorted(listing, key=lambda e: e.name)
    except OSError as exc:
        yield relative, None, exc.strerror or type(exc).__name__
        return
    for entry in entries:
        path = f"{relative}/{entry.name}" if relative else entry.name
        yield path, entry, ""
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            is_dir = False
        if is_dir:
            yield from _walk(root, path)


def check_tree(root: Path, forbidden: Forbidden) -> list[Problem]:
    """Every problem of the tree under ``root``; an empty list is the only way to pass."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("the root of the export is not a directory")
    problems: list[Problem] = []
    seen: set[tuple[str, str, str]] = set()

    def add(file: str, hits: list[_Hit]) -> None:
        # One problem per rule and place: the same id found in two forms is one find.
        for rule, where, hint in hits:
            if (file, rule, where) in seen:
                continue
            seen.add((file, rule, where))
            problems.append(Problem(file, rule, where, hint))

    for path, entry, error in _walk(root, ""):
        if entry is None:
            add(path, [("unreadable", "", f"the directory cannot be read: {error}")])
            continue
        add(path, _check_text(_text(os.fsencode(entry.name), False), forbidden))
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            add(path, [("unreadable", "", f"cannot be read: {exc.strerror}")])
            continue
        if stat.S_ISLNK(mode):
            add(path, [("symlink", "", "a symbolic link; it is not followed")])
            continue
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            add(path, [("special_file", "", "neither a file nor a directory")])
            continue
        try:
            with open(root / path, "rb", opener=_no_follow) as handle:
                data = handle.read()
        except OSError as exc:
            add(path, [("unreadable", "", f"cannot be read: {exc.strerror}")])
            continue
        hits = _check_text(_text(data, True), forbidden)
        add(path, hits)
        if entry.name == RESULT_FILE:
            add(path, rule_unreleased_finding(data, forbidden))
        add(path, _document_hits(data, forbidden, {rule for rule, _, _ in hits}))
    return problems


def _no_follow(path: str, flags: int) -> int:
    """Open without following a link put in the place of the file since it was listed."""
    return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
