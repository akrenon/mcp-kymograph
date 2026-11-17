"""No generated document uses a banned word as a word of its own.

The list is :data:`mcp_kymograph.report.BANNED_WORDS`: whole words, without case, never stems.
Three parts:

* **The generated documents.** Every document the fixtures make — the report, the attestation,
  the text of ``engagement status``, ``CUSTOMER-README.md`` in every page version of
  :data:`mcp_kymograph.handover.WORDINGS`, ``redactions.json`` and ``purged.json`` — read for its
  sentence words only: a value in a code span is data from the traffic or a file (a tool may be
  called ``secure_login``) and not a sentence of the tool's.
* **The signal reference pages**, under ``src/mcp_kymograph/data/signals/`` and as a bundle
  carries them, read in full: a page holds no traffic, every word on it is its author's, so
  nothing on it is excused — not a code span, not a fenced block.
* **The source.** Skipping code spans in a generated document holds only if the tool never puts
  its own prose in one. So the generators' source is read too: every string they hold
  (docstrings aside, and the words of the list itself) carries no banned word, and every code
  span they write is a placeholder filled from data or an identifier of
  :data:`mcp_kymograph.report.CODE_SPAN_IDENTIFIERS` — a banned word cannot pass by being moved
  into backticks. The scan reads string literals, f-string templates, the first argument of a
  span function called by name or as an attribute, and every other value handed to one: a
  constant (the module's own, or one imported from another module of the package, by name or
  as an attribute of that module; a tuple of strings hands each) is read as its strings; a
  local name is read as everything it is bound to in its scope, each branch as if handed itself
  — a loop or comprehension variable as an element of what it walks, a collection as what is
  put into it, an exception caught as refused unless the system raised it
  (:data:`SYSTEM_ERRORS`); an f-string of placeholders only, as each of its values; a number is
  no sentence; anything else must be read under a name of :data:`DATA_FIELDS` — a value from
  data — or be the result of a function of :data:`RESULTS_FROM_DATA`, or it is refused.
  It is a guard against prose slipping into a span, not against a deliberate evasion: a word split
  over two strings, or built at run time, is not caught here.
* **Nothing is taken over from the store or the evidence module's words.** A caveat, an
  attribution, an error and the problems a verify finds set what they read among their words;
  the report says each in its own (:data:`mcp_kymograph.report.CAVEAT_WORDS`), so the words of
  another module never stand among a document's.

Not read: the operator's own part of a report (section 9a, not yet made), the command line's
messages, ``README.md`` and ``docs/``.
"""

from __future__ import annotations

import ast
import dataclasses
import functools
import hashlib
import importlib
import json
import os
import re
import shutil
import sqlite3
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mcp_kymograph
from mcp_kymograph import engagement, evidence, handover, report, store

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

from customer_engagement import banned_in, make, sentence_words  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)
PACKAGE = Path(mcp_kymograph.__file__).parent
PAGES = PACKAGE / "data" / "signals"

#: The modules that write a document a customer reads: the report, the attestation, the status
#: (report.py), ``CUSTOMER-README.md`` (handover.py), ``redactions.json``'s descriptions, the
#: index's notes and ``purged.json`` (evidence.py), and the class titles the report states as
#: sentence words (finding_classes.py).
GENERATORS = ("report.py", "handover.py", "evidence.py", "finding_classes.py")

#: The functions that turn a value into a code span: :func:`mcp_kymograph.report._code`, and the
#: ``show`` that :func:`mcp_kymograph.report.status_lines` is handed (a code span in the report).
SPAN_FUNCTIONS = frozenset({"_code", "show"})

#: A code span in a string of the source, by its fence.
_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.*?[^`])\1(?!`)")
#: What a placeholder looks like in a template: ``{}`` for an f-string's value, ``{name}`` for
#: :meth:`str.format`.
_PLACEHOLDERS = re.compile(r"(?:\{\w*\})+")


@pytest.fixture(scope="module")
def made(tmp_path_factory):
    return make(tmp_path_factory.mktemp("banned"), NOW)


# -- the list and the check -------------------------------------------------------------------


def test_the_list_is_the_eleven_words_of_section_7():
    assert report.BANNED_WORDS == (
        "safe", "secure", "security", "vulnerable", "vulnerability", "exploit", "risk", "clean",
        "compliant", "certified", "guaranteed",
    )  # fmt: skip


@pytest.mark.parametrize(
    ("words", "found"),
    [
        ("The server is secure.", ["secure"]),
        ("No Security review; RISK and Exploit.", ["Security", "RISK", "Exploit"]),
        ("a non-compliant, clean-looking tool", ["compliant", "clean"]),
        ("A certificate was presented and certified.", ["certified"]),
        ("certificate, securely, risky, unsafe, exploited, cleanup, guarantees", []),
        ("a tool named secure_login or safe2", []),
    ],
)
def test_the_check_takes_whole_words_without_case_and_no_stems(words, found):
    assert banned_in(words) == found


def test_a_value_in_a_code_span_is_data_and_a_word_outside_is_not():
    assert not banned_in(sentence_words("[recorded] Tool `secure_login`, value `safe`."))
    assert banned_in(sentence_words("[recorded] Tool `x` is safe.")) == ["safe"]
    assert not banned_in(sentence_words("Text\n```\nthis example is secure\n```\nmore"))


def test_a_word_planted_in_a_generated_report_fails_and_certificate_passes(made):
    planted = made.report + "\n[derived] This engagement found the server safe.\n"
    passing = made.report + "\n[derived] This engagement saw a certificate.\n"

    assert banned_in(sentence_words(planted)) == ["safe"]
    assert not banned_in(sentence_words(passing))


# -- the documents ----------------------------------------------------------------------------


def test_the_report_has_no_banned_word(made):
    parsed = report.parse(made.report)

    assert parsed.sentences
    assert not banned_in(sentence_words(made.report))
    for sentence in parsed.sentences:
        assert not banned_in(sentence.words), sentence.line()


@pytest.mark.parametrize(
    ("spoil", "why"),
    [
        (Path.unlink, "not found under the runs directory"),
        (
            lambda path: path.write_bytes(path.read_bytes() + b"\n"),
            "its bytes are not the ones the store filed under this run",
        ),
    ],
    ids=["not-found", "changed"],
)
def test_why_a_recording_was_not_read_is_read_as_sentence_words(made, tmp_path, spoil, why):
    """The tool says in its own words why a recording was not read, so the check reads them."""
    runs = tmp_path / "runs"
    shutil.copytree(made.runs, runs)
    spoil(next(runs.rglob("events.jsonl")))

    text = report.render(
        report.build(engagement_path=made.held, store=made.database, runs_dir=runs, now=NOW)
    )

    assert f"was not read ({why}, looked for under the runs directory" in sentence_words(text)
    assert not banned_in(sentence_words(text))


def _not_json() -> tuple[bytes, str]:
    raw = b'{"type": "run_started", "a": "\\q"}\n'
    try:
        json.loads(raw)
    except ValueError as exc:
        return raw, str(exc)
    raise AssertionError("the line was read")


def test_what_the_json_reader_said_is_kept_apart_from_the_tool_s_words(tmp_path):
    raw, said = _not_json()
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "events.jsonl").write_bytes(raw)
    run = SimpleNamespace(run=hashlib.sha256(raw).hexdigest())
    filed = SimpleNamespace(recordings=lambda: {run.run: "run/events.jsonl"})

    (read,) = report._read_recordings(filed, [run], tmp_path).values()

    assert (read.state, read.why, read.detail) == ("unreadable", "a line is not JSON", said)
    assert "\\" in said


def test_a_report_on_a_recording_that_is_not_json_is_still_read_back(made, monkeypatch):
    _, said = _not_json()
    found = report._read_recordings

    def unread(held, runs, runs_dir):
        read = found(held, runs, runs_dir)
        return {
            **read,
            min(read): report._Recording("unreadable", "a line is not JSON", detail=said),
        }

    monkeypatch.setattr(report, "_read_recordings", unread)
    text = report.render(
        report.build(engagement_path=made.held, store=made.database, runs_dir=made.runs, now=NOW)
    )

    (sentence,) = [s for s in report.parse(text).sentences if "was not read (" in s.words]
    assert "was not read (a line is not JSON:" in sentence.words
    assert said in sentence.values


def _attested_with(made, tmp_path: Path, change) -> str:
    runs = tmp_path / "runs"
    shutil.copytree(made.runs, runs)
    undo = change(runs)
    try:
        return report.render_attestation(
            report.attest(
                store=made.database,
                engagement_path=made.held,
                bundle_dir=made.bundle,
                runs_dir=runs,
                now=NOW,
            )  # fmt: skip
        )
    finally:
        undo()


def test_a_refusals_file_the_reader_refuses_is_said_in_the_report_s_own_words(made, tmp_path):
    def refused(runs: Path):
        (runs / "refused").mkdir()
        (runs / "refused" / engagement.REFUSALS_FILE).write_text("not a secure refusal\n")
        return lambda: None

    text = _attested_with(made, tmp_path, refused)

    assert (
        f"could not be read ({report.REFUSED_BY_THE_READER}): its refusals are not counted"
        in sentence_words(text)
    )
    assert "secure" not in text, "the reader's reason, with what it read, is not taken over"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_refusals_file_that_cannot_be_opened_is_not_said_to_be_refused_by_the_reader(
    made, tmp_path
):
    """The system would not open the file: that is not the reader refusing what it holds. The
    report says it cannot be read, and what the system said stands as a value."""

    def locked(runs: Path):
        (runs / "locked").mkdir()
        refusals = runs / "locked" / engagement.REFUSALS_FILE
        refusals.write_text("")
        refusals.chmod(0)
        return lambda: refusals.chmod(0o600)

    text = _attested_with(made, tmp_path, locked)

    (sentence,) = [
        s for s in report.parse_attestation(text).sentences if "could not be read (" in s.words
    ]
    assert "could not be read (it cannot be read:" in sentence.words
    assert report.REFUSED_BY_THE_READER not in sentence.words
    assert os.strerror(13) in sentence.values
    assert os.strerror(13) not in sentence_words(text)


@pytest.mark.skipif(os.geteuid() == 0, reason="root lists a directory whatever its mode")
def test_a_directory_that_cannot_be_listed_is_said_in_words_and_the_system_s_reason_as_a_value(
    made, tmp_path
):
    def locked(runs: Path):
        (runs / "locked").mkdir()
        (runs / "locked").chmod(0)
        return lambda: (runs / "locked").chmod(0o700)

    text = _attested_with(made, tmp_path, locked)

    (sentence,) = [
        s for s in report.parse_attestation(text).sentences if "could not be read (" in s.words
    ]
    assert "could not be read (it cannot be listed:" in sentence.words
    assert os.strerror(13) in sentence.values
    assert os.strerror(13) not in sentence_words(text)


@pytest.mark.parametrize(
    ("raised", "in_words", "in_values"),
    [
        (
            store.StoreError("the store at /srv/me/clean-run is secure"),
            "its store cannot be read (it is not a store this version reads): nothing is compared",
            None,
        ),
        (
            sqlite3.DatabaseError("database disk image is malformed"),
            "its store cannot be read (SQLite:  ): nothing is compared",
            "database disk image is malformed",
        ),
    ],
    ids=["StoreError", "sqlite3.Error"],
)
def test_a_previous_store_that_cannot_be_read_is_said_where_its_kind_belongs(
    made, monkeypatch, raised, in_words, in_values
):
    """The store's own error is not taken over, the report says it in its words; SQLite's
    message is a value, in a span."""
    previous = made.bundle / evidence.STORE_FILE

    class Failing(report.Store):
        @classmethod
        def open_read_only(cls, path, *args, **kwargs):
            if Path(path) == previous:
                raise raised
            return super().open_read_only(path, *args, **kwargs)

    monkeypatch.setattr(report, "Store", Failing)
    (sentence,) = [
        s for s in _section_five(made, made.bundle).sentences if "store cannot be" in s.words
    ]

    assert in_words in sentence.words
    if in_values is None:
        assert sentence.values == (made.bundle.name,)
        assert "secure" not in sentence.text, "the store's error is not taken over"
    else:
        assert in_values in sentence.values
        assert in_values not in sentence.words


def test_every_caveat_the_store_may_set_has_the_report_s_words():
    caveats = {
        value
        for name, value in vars(store).items()
        if name.isupper() and isinstance(value, str) and re.match(r"[a-z_]+: ", value)
    }

    assert caveats == set(report.CAVEAT_WORDS)
    for caveat, words in report.CAVEAT_WORDS.items():
        flag = caveat.partition(":")[0]
        assert words.startswith(f"`{flag}`, "), flag
        assert not banned_in(words), flag


def _rendered(made, previous) -> str:
    built = report.build(
        engagement_path=made.held, store=made.database, runs_dir=made.runs, previous=previous,
        now=NOW,
    )  # fmt: skip
    return report.render(built)


def _section_five(made, previous) -> report.Section:
    return report.parse(_rendered(made, previous)).sections[4]


def _not_intact(made, tmp_path: Path) -> Path:
    previous = tmp_path / "previous"
    shutil.copytree(made.bundle, previous)
    (previous / "a secure note.txt").write_text("not packed\n")
    report_file = previous / "report.md"
    report_file.write_bytes(report_file.read_bytes() + b"\n")
    return previous


def test_a_previous_bundle_that_is_not_one_is_said_without_the_words_of_its_path(made):
    """A case found in review: what evidence.verify says sets the path among its words."""
    (sentence,) = _section_five(made, Path("/srv/me/clean-run/bundle")).sentences

    assert "was not compared: its index cannot be read by" in sentence.words
    assert not banned_in(sentence.words)
    assert sentence.text.endswith("`kymograph evidence verify` on the bundle `bundle` says why.")


def test_a_previous_bundle_not_intact_is_said_by_counts_of_its_files(made, tmp_path):
    (sentence,) = _section_five(made, _not_intact(made, tmp_path)).sentences

    assert "is not intact by" in sentence.words and "nothing of it is compared" in sentence.words
    assert not banned_in(sentence.words)
    assert {"changed", "unlisted", "intact"} <= set(sentence.values)
    assert sentence.text.endswith(
        "`kymograph evidence verify` on the bundle `previous` names each file and problem."
    )


@pytest.mark.parametrize("case", ["not a bundle", "not intact"])
def test_the_operator_s_path_to_the_previous_bundle_is_nowhere_in_the_report(made, tmp_path, case):
    """The customer's report names the previous bundle by its name, never by where the operator
    keeps it."""
    previous = (
        tmp_path / "clean-run" / "bundle" if case == "not a bundle" else _not_intact(made, tmp_path)
    )

    text = _rendered(made, previous)

    assert str(previous.parent) not in text
    assert previous.name in report.parse(text).sections[4].sentences[0].values


def test_a_bundle_name_with_two_spaces_stands_whole_in_its_span(made, tmp_path):
    """A regression test: a span keeps its spaces as they are."""
    previous = tmp_path / "two  spaces"
    shutil.copytree(made.bundle, previous)

    five = _section_five(made, previous)

    assert "two  spaces" in five.sentences[0].values


def test_a_bundle_name_with_a_backtick_is_read_back_unchanged(made, tmp_path):
    """A regression test: ``_code`` fences a name that holds a
    backtick, and ``report.parse`` reads it back as it was."""
    previous = tmp_path / "back`tick"
    shutil.copytree(made.bundle, previous)

    five = _section_five(made, previous)

    assert "back`tick" in five.sentences[0].values


#: A finding a comparison holds as new, made up: each identity field ``planted``.
PLANTED = store.Compared(
    identity=dict.fromkeys(store.IDENTITY_FIELDS, "planted"), before=None, after={}
)


def _attributed(made, monkeypatch, change) -> list[report.Sentence]:
    """Section 5 against the fixture's own bundle, the comparison changed by ``change`` and
    attributed by the store's own rule from what it then holds."""
    compared = store.compare_runs

    def changed(*args, **kwargs):
        diff = change(compared(*args, **kwargs))
        differs = bool(diff.new or diff.gone)
        attribution = store._attribute(diff.before, diff.after, diff.axes, differs)
        return dataclasses.replace(diff, attribution=attribution)

    monkeypatch.setattr(store, "compare_runs", changed)
    five = _section_five(made, made.bundle)
    attributed = [s for s in five.sentences if "attribution:" in s.words]
    assert attributed
    return attributed


def test_findings_that_differ_with_nothing_moved_are_put_down_to_nothing(made, monkeypatch):
    """Nothing recorded moved, yet a finding is new: the store attributes it to nothing, and the
    report says so in its own words (the store's note is not taken over)."""

    def one_new(diff):
        assert not diff.moved
        return dataclasses.replace(diff, new=(PLANTED,))

    for sentence in _attributed(made, monkeypatch, one_new):
        assert "attribution: none, nothing recorded moved, yet the findings differ" in (
            sentence.words
        )
        assert not banned_in(sentence.words)


def test_only_the_environment_moved_and_nothing_differs_is_put_down_to_that_axis(made, monkeypatch):
    """The flagged form is for a difference only; with nothing new or gone, the environment is
    the one axis that moved, and nothing is flagged."""

    def environment_moved(diff):
        axes = {name: {**axis, "moved": name == "environment"} for name, axis in diff.axes.items()}
        return dataclasses.replace(diff, axes=axes, new=(), gone=())

    for sentence in _attributed(made, monkeypatch, environment_moved):
        assert "attribution: the `environment` axis, the only one that moved." in sentence.text
        assert "flagged" not in sentence.words


def test_only_the_environment_moved_with_a_new_finding_is_flagged(made, monkeypatch):
    def environment_moved(diff):
        axes = {name: {**axis, "moved": name == "environment"} for name, axis in diff.axes.items()}
        return dataclasses.replace(diff, axes=axes, new=(PLANTED,))

    for sentence in _attributed(made, monkeypatch, environment_moved):
        assert "flagged, not put down to the server" in sentence.words


@pytest.mark.parametrize("which", ["attestation", "attestation_with_session"])
def test_the_attestation_has_no_banned_word(made, which):
    text = getattr(made, which)
    parsed = report.parse_attestation(text)

    assert parsed.sentences
    assert not banned_in(sentence_words(text))


def test_the_status_text_has_no_banned_word(made):
    assert made.status.strip()
    assert not banned_in(made.status)


@pytest.mark.parametrize("which", ["redactions", "purged"])
def test_redactions_json_and_purged_json_have_no_banned_word(made, which):
    text = getattr(made, which)

    assert text.strip()
    assert not banned_in(text)


@pytest.mark.parametrize("version", sorted(handover.WORDINGS))
def test_the_customer_readme_has_no_banned_word_in_any_page_version(made, version):
    text = made.readmes[version]
    labels = [words for _, words in handover.WORDINGS[version].labels]
    # A name or number after its label is a value from the bundle, not a word of the page's.
    lines = [
        next((label for label in labels if line.startswith(f"- {label}: ")), line)
        for line in text.splitlines()
    ]

    assert not banned_in(sentence_words("\n".join(lines)))


def test_the_handover_bundle_s_readme_is_the_current_page_version(made):
    written = (made.handover / handover.CUSTOMER_README).read_text()

    assert written == made.readmes[handover.PAGE_VERSION]


def pages_with_a_banned_word(directory: Path) -> list[tuple[str, list[str]]]:
    """Each reference page under ``directory`` that holds a banned word anywhere in its text."""
    found = []
    for page in sorted(directory.glob("*.md")):
        words = banned_in(page.read_text(encoding="utf-8"))
        if words:
            found.append((page.name, words))
    return found


def test_the_signal_reference_pages_have_no_banned_word_anywhere():
    assert sorted(PAGES.glob("*.md"))
    assert pages_with_a_banned_word(PAGES) == []


@pytest.mark.parametrize("where", ["bundle", "handover"])
def test_the_pages_a_bundle_carries_have_no_banned_word_anywhere(made, where):
    carried = getattr(made, where) / "reference"

    assert sorted(carried.glob("*.md"))
    assert pages_with_a_banned_word(carried) == []


@pytest.mark.parametrize(
    "planted",
    [
        "The value `safe` stands in a code span.",
        "A double fence ``it is secure`` around a span.",
        "```\nthis example is clean\n```",
        "~~~\nan example with no risk\n~~~",
        "    an indented line that is compliant",
    ],
    ids=["span", "double-span", "backtick-block", "tilde-block", "indented"],
)
def test_a_word_planted_on_a_page_fails_wherever_it_stands(tmp_path, planted):
    page = sorted(PAGES.glob("*.md"))[0]
    copy = tmp_path / page.name
    copy.write_text(page.read_text(encoding="utf-8") + "\n" + planted + "\n", encoding="utf-8")

    assert pages_with_a_banned_word(tmp_path) != []
    assert pages_with_a_banned_word(PAGES) == []


# -- the source -------------------------------------------------------------------------------


def _docstrings(tree: ast.AST) -> set[int]:
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def _template(node: ast.JoinedStr) -> str:
    """An f-string's literal parts, with ``{}`` where a value goes."""
    return "".join(part.value if isinstance(part, ast.Constant) else "{}" for part in node.values)


def _the_list(node: ast.AST) -> bool:
    """Whether ``node`` is the banned list itself: ``BANNED_WORDS`` assigned a tuple, list or set
    of single words, the one place the words stand as words. Any other name, and any element that
    is not one word, is read like every other string."""
    if not (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "BANNED_WORDS"
        and isinstance(node.value, (ast.Tuple, ast.List, ast.Set))
    ):
        return False
    return all(
        isinstance(element, ast.Constant)
        and isinstance(element.value, str)
        and re.fullmatch(r"\w+", element.value)
        for element in node.value.elts
    )


def strings(source: str) -> Iterator[tuple[int, str]]:
    """Every string a module's source holds, but its docstrings and the banned list itself: each
    constant, and each f-string as one template (its literal parts are not read apart, so a code
    span split by a value is still one span)."""
    tree = ast.parse(source)
    skipped = _docstrings(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            skipped.update(id(part) for part in node.values if isinstance(part, ast.Constant))
        elif _the_list(node):
            skipped.update(id(inner) for inner in ast.walk(node))
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            yield node.lineno, _template(node)
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in skipped
        ):
            yield node.lineno, node.value


def banned_in_source(source: str) -> list[tuple[int, str]]:
    return [(line, word) for line, text in strings(source) for word in banned_in(text)]


def _strings_of(value: ast.expr | None) -> tuple[str, ...] | None:
    """The string, or the strings of a tuple, list or set of strings, a constant holds; none
    for a number or a truth value, which is not a sentence."""
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return (value.value,)
    if isinstance(value, ast.Constant) and isinstance(value.value, (int, float)):
        return ()
    if isinstance(value, (ast.Tuple, ast.List, ast.Set)) and all(
        isinstance(element, ast.Constant) and isinstance(element.value, str)
        for element in value.elts
    ):
        return tuple(element.value for element in value.elts)
    return None


def _module_strings(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """The module-level names assigned a string constant, or a tuple, list or set of them, as a
    span function may be handed (``", ".join(PROVIDED)`` hands each of its strings)."""
    found = {}
    for node in tree.body:
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if value else []
        held = _strings_of(value)
        if held is not None:
            for target in targets:
                if isinstance(target, ast.Name):
                    found[target.id] = held
    return found


def _package_module(dotted: str) -> Path | None:
    """The source of a module of this package by its dotted name, or None for any other."""
    first, _, rest = dotted.partition(".")
    if first != PACKAGE.name:
        return None
    base = PACKAGE.joinpath(*rest.split(".")) if rest else PACKAGE
    for source in (base.with_suffix(".py"), base / "__init__.py"):
        if source.is_file():
            return source
    return None


def _imports(tree: ast.Module) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    """What a module imports from this package: each name bound to a name of another module
    (``from mcp_kymograph.engagement import REFUSALS_FILE``, or ``from .engagement import …`` as
    a module at the package's top level writes it), and each name bound to a module
    (``from mcp_kymograph import store as store_module``, ``import mcp_kymograph.store as s``)."""
    names: dict[str, tuple[str, str]] = {}
    modules: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level > 1:
                continue
            base = (
                PACKAGE.name + (f".{node.module}" if node.module else "")
                if node.level
                else node.module or ""
            )
            for alias in node.names:
                bound = alias.asname or alias.name
                if _package_module(f"{base}.{alias.name}") is not None:
                    modules[bound] = f"{base}.{alias.name}"
                elif _package_module(base) is not None:
                    names[bound] = (base, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and _package_module(alias.name) is not None:
                    modules[alias.asname] = alias.name
    return names, modules


@functools.cache
def _constant_of(dotted: str, name: str) -> tuple[str, ...] | None:
    """The strings ``name`` holds as a constant of the package's module ``dotted``, following
    that module's own imports from the package; None when it is not such a constant."""
    tree = ast.parse(_package_module(dotted).read_text(encoding="utf-8"))
    held = _module_strings(tree).get(name)
    if held is not None:
        return held
    names, _ = _imports(tree)
    return _constant_of(*names[name]) if name in names else None


#: The names a value handed to a span function is read under when it is not spelled out in the
#: source: a variable, an attribute, a key of a mapping read from a file or the store. Each is a
#: value from data, never a sentence of the tool's; a new entry is a decision, not a wave-through.
#: Not here, on purpose: ``why``, ``note``, ``caveat``, ``summary``, ``exc`` (the tool's prose),
#: and ``reason``, which ``RefusalsCount`` and ``RecheckItem`` hold as a sentence.
_DATA_FIELDS = """
    actions after answer at_utc auth author axis before call cause causes chain code command
    counted decided detail digest endpoint_certificates engagement engagement_digest
    engagement_id engagement_id_declared entry env_name era file_sha256 fleet fleet_results
    fleets from host id identity index_digest isolation isolations item key kind launch_digest
    list locator manifest min_interval_seconds moved name now outcome paced pacing page path
    paths port ports provenance refused_utc role run runs runs_by_state runs_per_origin said
    sandbox_image scenario scenario_digest scenario_path scenarios script script_digest
    script_vars server server_identity_kind server_version server_version_kind set_utc sha256
    signal source started state statement states status statuses store_schema store_sha256
    supersedes target target_image targets tls_versions tool_content tool_version total tz until
    value version window window_from window_until
"""
DATA_FIELDS = frozenset(_DATA_FIELDS.split())

#: The names the tool's prose is read under, never data: a key of one of these in a mapping is
#: refused even where the mapping is data (``auth["token"]``, ``decided.get("reason")``).
PROSE_NAMES = frozenset({"why", "note", "caveat", "summary", "exc", "token", "reason"})

#: Values handed to a span function that are let through until their treatment is decided, each as
#: :func:`ast.unparse` writes it: the ``why`` of a recorded ``paced`` event (``interval``,
#: ``origin_busy``) is data, read under a name :data:`DATA_FIELDS` leaves out on purpose; it is
#: also read where the waits are grouped by it (``event.get('why')``).
ASKED = frozenset({"waits[0].get('why')", "event.get('why')"})

#: Calls that hand on the value they are given, made text: ``str(x)``, ``utc_text(x)``,
#: ``json.dumps(x)``, ``", ".join(x)`` (each element).
_PASSING_ON = frozenset({"str", "utc_text", "dumps", "join"})

#: Calls whose result is a number whatever they are given, and a number is not a sentence.
_NUMBERS = frozenset({"sum", "round", "len", "int", "float"})


def _called(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _is_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.JoinedStr) or (
        isinstance(node, ast.Constant) and isinstance(node.value, str)
    )


def _binds(target: ast.AST, name: str) -> bool:
    """Whether an assignment to ``target`` binds ``name``: the name itself, or one of a tuple or
    list unpacked into (``x[k] = v`` binds no name, it changes what ``x`` holds)."""
    if isinstance(target, ast.Name):
        return target.id == name
    if isinstance(target, ast.Starred):
        return _binds(target.value, name)
    if isinstance(target, (ast.Tuple, ast.List)):
        return any(_binds(element, name) for element in target.elts)
    return False


def _branches(value: ast.expr) -> list[ast.expr]:
    """A value's branches apart: ``x if y else "none"`` is ``x`` and ``"none"``."""
    found, pending = [], [value]
    while pending:
        branch = pending.pop()
        if isinstance(branch, ast.IfExp):
            pending += [branch.body, branch.orelse]
        elif isinstance(branch, ast.BoolOp):
            pending += branch.values
        else:
            found.append(branch)
    return found


def _base(node: ast.expr) -> str | None:
    """The local a change reaches: ``x`` of ``x[k]``, ``x[k][j]`` and ``x.setdefault(k, [])``."""
    while True:
        if isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            node = node.func.value
        else:
            return node.id if isinstance(node, ast.Name) else None


def _keys(target: ast.expr) -> list[ast.expr]:
    """The keys of ``x[k][j]``, outermost last."""
    keys = []
    while isinstance(target, ast.Subscript):
        keys.append(target.slice)
        target = target.value
    return keys


#: How a local is bound: assigned a value; given one element of a collection at a time (a loop,
#: a comprehension, an unpacking); an exception caught. And how a collection is filled: it holds
#: a value (``x[k] = v``, ``x.append(v)``, holding ``k`` and ``v``), or each element of one
#: (``x.extend(c)``, ``x.update(c)``).
_ASSIGNED, _ELEMENT, _CAUGHT, _HOLDS, _HOLDS_EACH = "assigned", "element", "caught", "holds", "each"

#: The methods that put what they are given into the collection they are called on.
_FILLING = frozenset({"append", "add", "insert", "appendleft", "setdefault"})
_FILLING_EACH = frozenset({"extend", "update"})

#: The nodes that open a scope of their own: a name bound inside is not the outer one's.
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)


def _own(scope: ast.AST) -> Iterator[ast.AST]:
    """The nodes of ``scope`` that are not in a scope nested in it."""
    pending = list(ast.iter_child_nodes(scope))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(node, (*_FUNCTIONS, ast.ClassDef, *_COMPREHENSIONS)):
            pending += ast.iter_child_nodes(node)


def _assigned(target: ast.expr, value: ast.expr, name: str) -> list[tuple[str, ast.expr]]:
    """What assigning ``value`` to ``target`` binds ``name`` to, or fills it with."""
    if isinstance(target, ast.Name):
        return [(_ASSIGNED, branch) for branch in _branches(value)] if target.id == name else []
    if isinstance(target, (ast.Tuple, ast.List)):
        if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts):
            return [
                found
                for inner, given in zip(target.elts, value.elts, strict=True)
                for found in _assigned(inner, given, name)
            ]
        return [(_ELEMENT, value)] if _binds(target, name) else []
    if isinstance(target, ast.Subscript) and _base(target) == name:
        return [(_HOLDS, given) for given in (*_keys(target), value)]
    return []


def _bound_in(scope: ast.AST, name: str) -> list[tuple[str, ast.expr | None]]:
    """Every binding of ``name`` in ``scope`` itself, and everything put into it there."""
    if isinstance(scope, _COMPREHENSIONS):
        return [
            (_ELEMENT, generator.iter)
            for generator in scope.generators
            if _binds(generator.target, name)
        ]
    found: list[tuple[str, ast.expr | None]] = []
    for node in _own(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                found += _assigned(target, node.value, name)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            if node.value is not None:
                found += _assigned(node.target, node.value, name)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            if _binds(node.target, name):
                found.append((_ELEMENT, node.iter))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            found += [
                (_ASSIGNED, item.context_expr)
                for item in node.items
                if item.optional_vars is not None and _binds(item.optional_vars, name)
            ]
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            found.append((_CAUGHT, node.type))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _base(node.func.value) == name
        ):
            if node.func.attr in _FILLING:
                found += [(_HOLDS, given) for given in node.args]
            elif node.func.attr in _FILLING_EACH:
                found += [(_HOLDS_EACH, given) for given in node.args]
    return found


def _bindings(
    scopes: tuple[ast.AST, ...], name: str
) -> tuple[tuple[ast.AST, ...], list[tuple[str, ast.expr | None]]]:
    """The bindings of the local ``name`` in the innermost of ``scopes`` (innermost first: a
    comprehension, a function, the module) that binds it, with the scopes from that one out."""
    for at, scope in enumerate(scopes):
        found = _bound_in(scope, name)
        if found:
            return scopes[at:], found
    return (), []


#: Calls that hand on the elements of the collection they are given: ``sorted(x)``,
#: ``x.items()`` and the like.
_PASSING_ELEMENTS = frozenset(
    {
        "sorted",
        "list",
        "set",
        "tuple",
        "frozenset",
        "reversed",
        "enumerate",
        "zip",
        "Counter",
        "dict",
    }
)
_VIEWS = frozenset({"items", "keys", "values"})

#: Exceptions raised by the system or a library, never by this package: what ``str()`` of one
#: says is the system's reason, a value, and is shown in a span as one. The package's own
#: errors set their words around what they read, and are refused.
SYSTEM_ERRORS = frozenset({"sqlite3.Error"})

#: Functions whose result is a value from data, never a sentence of the tool's; a new entry is a
#: decision, as for :data:`DATA_FIELDS`. ``reference_page``: the path of a reference page in the
#: bundle, by signal id. ``command``: a command line, ``shlex.join`` of recorded values.
#: ``keyed``: an engagement file's targets and scenarios, each as JSON. ``_chosen``: the store's
#: runs by entry and scenario. ``_identity_of``: the identity of a triage row of the store.
RESULTS_FROM_DATA = frozenset({"reference_page", "command", "keyed", "_chosen", "_identity_of"})


def _data_name(given: ast.expr) -> str | None:
    """The name a value is read under: a variable's, an attribute's, the key of ``x["key"]`` or
    ``x.get("key")``, a getter's (``store.runs()``), through a slice or index and through a call
    of :data:`_PASSING_ON`."""
    if isinstance(given, ast.Name):
        return given.id
    if isinstance(given, ast.Attribute):
        return given.attr
    if isinstance(given, ast.Subscript):
        key = given.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return _data_name(given.value)
    if isinstance(given, ast.Call) and given.args:
        if _called(given) == "get":
            key = given.args[0]
            return key.value if isinstance(key, ast.Constant) else None
        if _called(given) in _PASSING_ON:
            return _data_name(given.args[0])
    if isinstance(given, ast.Call) and isinstance(given.func, ast.Attribute):
        return given.func.attr
    return None


def _prose_key(given: ast.expr) -> str | None:
    """The key of ``x["key"]`` or ``x.get("key")`` when it is one of :data:`PROSE_NAMES`."""
    if isinstance(given, ast.Subscript):
        key = given.slice
    elif isinstance(given, ast.Call) and _called(given) == "get" and given.args:
        key = given.args[0]
    else:
        return None
    if isinstance(key, ast.Constant) and key.value in PROSE_NAMES:
        return key.value
    return None


def _template_allowed(template: str) -> bool:
    """An f-string's template that only places values: placeholders, spaces between them."""
    return bool(re.fullmatch(r" *(?:\{\} *)+", template))


def _runtime_strings(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (int, float)):
        return ()
    if isinstance(value, (tuple, list, set, frozenset)) and all(
        isinstance(item, (str, int, float)) for item in value
    ):
        return tuple(item for item in value if isinstance(item, str))
    return None


@functools.cache
def _module_constant(dotted: str, name: str) -> tuple[str, ...] | None:
    """The strings a constant of the package's module ``dotted`` holds: read from the source
    where it is spelled out, and otherwise, for a name the module assigns at its top (a tuple of
    other constants), from the module as imported."""
    held = _constant_of(dotted, name)
    if held is not None:
        return held
    tree = ast.parse(_package_module(dotted).read_text(encoding="utf-8"))
    for node in tree.body:
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
            if isinstance(node, ast.AnnAssign)
            else []
        )
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            return _runtime_strings(getattr(importlib.import_module(dotted), name, None))
    return None


class _Spans:
    """What every value handed to a span function in one module's source is, read as the module
    docstring says."""

    def __init__(self, tree: ast.Module, module: str | None) -> None:
        self.module = module
        self.constants = _module_strings(tree)
        self.names, self.modules = _imports(tree)
        self.found: list[tuple[int, str]] = []

    def constant(self, given: ast.expr) -> tuple[str, ...] | None:
        if isinstance(given, ast.Name):
            if given.id in self.constants:
                return self.constants[given.id]
            if given.id in self.names:
                return _module_constant(*self.names[given.id])
            if self.module is not None:
                return _module_constant(self.module, given.id)
        elif (
            isinstance(given, ast.Attribute)
            and isinstance(given.value, ast.Name)
            and given.value.id in self.modules
        ):
            return _module_constant(self.modules[given.value.id], given.attr)
        return None

    def hit(self, line: int, given: ast.expr) -> None:
        """``given`` read under its data name, or found."""
        name = _data_name(given)
        if isinstance(given, ast.Call) and _called(given) in RESULTS_FROM_DATA:
            return
        if name not in DATA_FIELDS and ast.unparse(given) not in ASKED:
            self.found.append((line, ast.unparse(given)))

    def local(self, given: ast.expr, scopes: tuple[ast.AST, ...]) -> ast.Name | None:
        """The local ``x`` of ``x[k]`` or ``x.get(k)``, when ``x`` is bound here."""
        if isinstance(given, ast.Subscript) or (
            isinstance(given, ast.Call) and _called(given) == "get"
        ):
            base = given.value if isinstance(given, ast.Subscript) else given.func.value
            if isinstance(base, ast.Name) and _bindings(scopes, base.id)[1]:
                return base
        return None

    def read(
        self,
        line: int,
        given: ast.expr,
        scopes: tuple[ast.AST, ...],
        seen: frozenset[tuple[int, str]] = frozenset(),
    ) -> None:
        if isinstance(given, ast.JoinedStr):
            if not _template_allowed(_template(given)):
                self.found.append((line, _template(given)))
                return
            # Placeholders only: each value is handed to the span as it stands.
            for part in given.values:
                if isinstance(part, ast.FormattedValue):
                    self.read(line, part.value, scopes, seen)
            return
        if isinstance(given, ast.Constant):
            text = given.value
            if isinstance(text, str) and text.strip() and not _allowed(text):
                self.found.append((line, text))
            return  # otherwise a number, a truth value, nothing: not a sentence
        if isinstance(given, ast.BoolOp):
            for value in given.values:
                self.read(line, value, scopes, seen)
            return
        if isinstance(given, ast.IfExp):
            self.read(line, given.body, scopes, seen)
            self.read(line, given.orelse, scopes, seen)
            return
        if isinstance(given, ast.BinOp):
            self.read(line, given.left, scopes, seen)
            self.read(line, given.right, scopes, seen)
            return
        held = self.constant(given)
        if held is not None:
            self.found += [(line, text) for text in held if not _allowed(text)]
            return
        if isinstance(given, ast.Call) and _called(given) in _NUMBERS:
            return
        if isinstance(given, (*_COMPREHENSIONS, ast.Starred)):
            self.elements(line, given, scopes, seen)
            return
        if isinstance(given, ast.Call) and _called(given) == "next" and given.args:
            # one element of the iterator, or the default
            self.elements(line, given.args[0], scopes, seen)
            for default in given.args[1:]:
                self.read(line, default, scopes, seen)
            return
        if isinstance(given, ast.Call) and _called(given) in _PASSING_ON and given.args:
            if _called(given) == "join":
                self.elements(line, given.args[0], scopes, seen)
            else:
                self.read(line, given.args[0], scopes, seen)
            return
        if isinstance(given, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            self.elements(line, given, scopes, seen)
            return
        if isinstance(given, ast.Name) and self.followed(line, given, scopes, seen, False):
            return
        if _prose_key(given) and ast.unparse(given) not in ASKED:
            self.found.append((line, ast.unparse(given)))
            return
        local = self.local(given, scopes)
        if local is not None:
            self.followed(line, local, scopes, seen, True)
            return
        self.hit(line, given)

    def followed(
        self,
        line: int,
        given: ast.Name,
        scopes: tuple[ast.AST, ...],
        seen: frozenset[tuple[int, str]],
        elements: bool,
    ) -> bool:
        """Read a local through its bindings, each as if handed itself (or, with ``elements``,
        as a collection whose elements are handed); False for a name nothing binds here."""
        outer, bindings = _bindings(scopes, given.id)
        if not bindings:
            return False
        key = (id(outer[0]), given.id)
        if key in seen:
            return True
        inner = seen | {key}
        for how, value in bindings:
            if how == _CAUGHT:
                if value is None or ast.unparse(value) not in SYSTEM_ERRORS:
                    self.found.append((line, given.id))
            elif how == _HOLDS:
                self.read(line, value, outer, inner)
            elif how in (_ELEMENT, _HOLDS_EACH) or elements:
                self.elements(line, value, outer, inner)
            else:
                self.read(line, value, outer, inner)
        return True

    def elements(
        self,
        line: int,
        given: ast.expr,
        scopes: tuple[ast.AST, ...],
        seen: frozenset[tuple[int, str]],
    ) -> None:
        """Read what a collection hands, one element at a time: a constant's strings, a
        comprehension's element, a literal's elements, or the collection's own data name."""
        held = self.constant(given)
        if held is not None:
            self.found += [(line, text) for text in held if not _allowed(text)]
            return
        if isinstance(given, (ast.Constant, ast.JoinedStr)):
            self.read(line, given, scopes, seen)
            return
        if isinstance(given, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            self.read(line, given.elt, (given, *scopes), seen)
            return
        if isinstance(given, ast.DictComp):
            self.read(line, given.key, (given, *scopes), seen)
            self.read(line, given.value, (given, *scopes), seen)
            return
        if isinstance(given, (ast.Tuple, ast.List, ast.Set)):
            for element in given.elts:
                self.read(line, element, scopes, seen)
            return
        if isinstance(given, ast.Dict):
            for element in (*given.keys, *given.values):
                if element is not None:
                    self.read(line, element, scopes, seen)
            return
        if isinstance(given, ast.BinOp):
            self.elements(line, given.left, scopes, seen)
            self.elements(line, given.right, scopes, seen)
            return
        if isinstance(given, ast.Starred):
            self.elements(line, given.value, scopes, seen)
            return
        if isinstance(given, (ast.BoolOp, ast.IfExp)):
            for branch in _branches(given):
                self.elements(line, branch, scopes, seen)
            return
        if isinstance(given, ast.Call):
            called = _called(given)
            if called in _VIEWS and isinstance(given.func, ast.Attribute):
                self.elements(line, given.func.value, scopes, seen)
                return
            if called in _PASSING_ELEMENTS:
                for argument in given.args:
                    self.elements(line, argument, scopes, seen)
                return
        if isinstance(given, ast.Name) and self.followed(line, given, scopes, seen, True):
            return
        if _prose_key(given) and ast.unparse(given) not in ASKED:
            self.found.append((line, ast.unparse(given)))
            return
        local = self.local(given, scopes)
        if local is not None:
            self.followed(line, local, scopes, seen, True)
            return
        self.hit(line, given)


def _scopes(tree: ast.AST) -> Iterator[tuple[ast.AST, tuple[ast.AST, ...]]]:
    """Every node with the scopes it stands in, innermost first, the module last."""
    pending: list[tuple[ast.AST, tuple[ast.AST, ...]]] = [(tree, (tree,))]
    while pending:
        node, scopes = pending.pop()
        yield node, scopes
        inner = (node, *scopes) if isinstance(node, (*_FUNCTIONS, *_COMPREHENSIONS)) else scopes
        pending += [(child, inner) for child in ast.iter_child_nodes(node)]


def _allowed(content: str) -> bool:
    return bool(_PLACEHOLDERS.fullmatch(content)) or content in report.CODE_SPAN_IDENTIFIERS


def spans_not_allowed(source: str, module: str | None = None) -> list[tuple[int, str]]:
    """Every code span the source writes that is neither a placeholder nor an identifier of
    :data:`~mcp_kymograph.report.CODE_SPAN_IDENTIFIERS`, nor a value read under a name of
    :data:`DATA_FIELDS`: spelled out in a string between backticks, or handed to a function that
    makes a code span of it."""
    found = []
    for line, text in strings(source):
        for match in _SPAN.finditer(text):
            content = match.group(2).strip(" ")
            if not _allowed(content):
                found.append((line, content))
    tree = ast.parse(source)
    spans = _Spans(tree, module)
    for node, scopes in _scopes(tree):
        if isinstance(node, ast.Call) and node.args and _called(node) in SPAN_FUNCTIONS:
            spans.read(node.lineno, node.args[0], scopes)
    return sorted(found + spans.found)


@pytest.mark.parametrize("module", GENERATORS)
def test_the_generators_strings_hold_no_banned_word(module):
    assert banned_in_source((PACKAGE / module).read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("module", GENERATORS)
def test_every_code_span_the_generators_write_is_a_placeholder_or_an_identifier(module):
    source = (PACKAGE / module).read_text(encoding="utf-8")

    assert spans_not_allowed(source, f"{PACKAGE.name}.{module.removesuffix('.py')}") == []


def test_the_identifiers_are_identifiers_and_hold_no_banned_word():
    for identifier in report.CODE_SPAN_IDENTIFIERS:
        assert not banned_in(identifier), identifier
        # a name, or a command of up to three words (``kymograph evidence verify``)
        assert re.fullmatch(r"[\w./:-]+(?: [\w./:-]+){0,2}", identifier), identifier


@pytest.mark.parametrize(
    "source",
    [
        "words = f\"Tool {_code(name)} is {_code('secure')}.\"",
        'words = f"Tool {_code(name)} is `secure`."',
        'words = "the page is `safe` to read"',
        'words = f"value `{value} is clean`"',
        'words = _code(f"risk {value}")',
        'words = show("guaranteed")',
        "words = f\"run {_code('an unlisted phrase')}\"",
        'words = report._code("the server is safe")',
        'words = self.show("clean")',
        'NOTE = "a clean bill"\nwords = f"see {_code(NOTE)}"',
        'NOTE: str = "a risk"\nwords = show(NOTE)',
        "from mcp_kymograph.store import CERTIFICATE_CHANGED\nwords = _code(CERTIFICATE_CHANGED)",
        'from mcp_kymograph import store as compared\nwords = f"{_code(compared.SCENARIO_DRIFT)}"',
        "import mcp_kymograph.store as compared\nwords = show(compared.LISTING_CAPPED)",
        "from .store import FINDINGS_CAPPED as capped\nwords = report._code(capped)",
        'words = f"not read ({_code(recording.why)}, looked for"',
        'def f():\n    note = "nothing moved, and nothing differs"\n    return _code(note)',
        'def f(x):\n    kind = x.value if x else "unknown to this version"\n    return show(kind)',
        "words = _code(caveat)",
        "words = _code(str(exc))",
        "words = _code(verified.summary())",
        'words = _code(note or "none needed")',
        'words = _code(", ".join(caveats))',
        'def f(v):\n    why = v.summary() if v else "none"\n    return _code(why)',
        'words = _code(f"{verified.summary()}")',
        'words = show(f"{counted.unreadable}")',
        "words = _code(counted.unreadable)",
        'def f(text):\n    return " ".join(_code(token) for token in text.split())',
        # a fallback word is no identifier
        'def f(x):\n    answer = x.get("outcome") if x else "none"\n    return _code(answer)',
        # a local is read through what it is assigned, not taken for data by its own name
        "def f(recording):\n    detail = recording.why\n    return _code(detail)",
        "def f(r):\n    detail = r.why if r else None\n    detail = detail or r.note\n"
        "    return show(detail)",
        "def f(r):\n    s = r.summary()\n    return _code(s)",
        # a loop or comprehension variable is read as an element of what it walks
        'def f(diff):\n    return ", ".join(_code(s) for s in diff.caveats["new"])',
        "def f(diff):\n    for c in diff.notes:\n        show(c)",
        "def f(diff):\n    for name, why in diff.items():\n        show(why)",
        "def f(rows):\n    said = []\n    for row in rows:\n        said.append(row.why)\n"
        '    return _code(", ".join(said))',
        "def f(rows):\n    said = {}\n    for row in rows:\n        said[row.name] = row.note\n"
        "    return [_code(value) for value in said.values()]",
        "def f(store):\n    try:\n        store.read()\n    except StoreError as error:\n"
        "        return _code(str(error))",
        # ``reason`` is no data name: RefusalsCount.reason and RecheckItem.reason are sentences
        "words = _code(counted.reason)",
        "words = show(item.reason)",
        # a local is read through what is put into it, whatever key it is read under
        'def f(row):\n    said = {}\n    said["path"] = row.note\n    return _code(said["path"])',
        'def f(row):\n    said = {}\n    said["path"] = row.note\n'
        '    return _code(said.get("path"))',
        'def f(row):\n    said = {"path": row.why}\n    return show(said["path"])',
        # a key the tool's prose is read under, though the mapping is data
        'def f(recording):\n    auth = recording.auth\n    return _code(auth["token"])',
        "def f(recording):\n    decided = recording.decided\n"
        '    return _code(decided.get("reason"))',
        # ... and handed on through a local: ``decided`` is a data field the scan follows, the
        # ``reason`` read from it is the tool's prose all the same
        "def f(recording):\n    decided = recording.decided\n"
        '    reason = decided.get("reason")\n    return show(reason)',
        # a prose key read from an attribute, through a local: refused before PROSE_NAMES too
        # (the name it is read under, ``reason``, is no data field); kept so it stays refused
        'def f(recording):\n    reason = recording.decided.get("reason")\n    return show(reason)',
    ],
)
def test_prose_moved_into_a_code_span_is_refused(source):
    assert spans_not_allowed(source)


@pytest.mark.parametrize(
    "source",
    [
        'words = f"Tool {_code(name)} at {_code(locator)}."',
        "words = f\"no {_code('step_called')} event, `{value}` and `{other}`\"",
        'words = "lists `index.json` and `{listed}`"',
        'words = _code(", ".join(entry.path))',
        "words = _code(False)",
        'words = report._code("step_called")',
        'FIELD = "run_started"\nwords = f"in {_code(FIELD)}"',
        "words = _code(run.server)",
        "words = _code(str(round(total, 3)))",
        "from mcp_kymograph.engagement import REFUSALS_FILE\nwords = _code(REFUSALS_FILE)",
        "from mcp_kymograph import engagement\nwords = show(engagement.ENDPOINT_DEFAULT_SCHEME)",
        "from .pacing import DEFAULT_RUNS_PER_ORIGIN\nwords = _code(DEFAULT_RUNS_PER_ORIGIN)",
        'single = "`"',
        'markup = "<>[]*_\\\\|`#"',
        # a loop variable over data is data, and a key names a field of data
        "def f(runs):\n    for run in runs:\n        _code(run.server)",
        'def f(x):\n    window = x.get("window") or {}\n    return _code(window.get("from"))',
        "def f(store):\n    try:\n        store.read()\n    except sqlite3.Error as exc:\n"
        "        detail = str(exc)\n        return _code(detail)",
        "def f(values):\n    return _code(sum(float(n) for n in values))",
        "from mcp_kymograph.masking import PERSONAL_KINDS\n"
        "words = [_code(kind) for kind in PERSONAL_KINDS]",
        "from mcp_kymograph.engagement import REFUSAL_REASONS\n"
        "def f(record):\n"
        "    reason = next((known for known in REFUSAL_REASONS if known == record.reason), None)\n"
        "    return _code(reason)",
    ],
)
def test_a_placeholder_an_identifier_and_the_span_machinery_pass(source):
    assert spans_not_allowed(source) == []


def test_the_data_fields_are_sorted_and_leave_out_the_tool_s_prose():
    assert _DATA_FIELDS.split() == sorted(DATA_FIELDS)
    assert not PROSE_NAMES & DATA_FIELDS
    assert not [name for name in DATA_FIELDS if len(name) == 1], "a loop variable is followed"


def test_the_stop_reasons_of_the_report_are_those_eras_allows():
    """:data:`~mcp_kymograph.report.ERA_STOP_REASONS` names every reason a detection may stop
    with: :data:`mcp_kymograph.eras.STOP_REASONS`, which a stopping ``Detection`` is held to
    where it is made."""
    from mcp_kymograph import eras

    assert set(report.ERA_STOP_REASONS) == eras.STOP_REASONS
    assert len(report.ERA_STOP_REASONS) == len(eras.STOP_REASONS)
    assert set(report.ERA_STOP_REASONS) <= report.CODE_SPAN_IDENTIFIERS


def test_every_reason_eras_writes_is_one_it_allows():
    """At test time, without running the path: every ``reason=`` of a call in ``eras`` is a
    name (or ``eras.X``) of a member of :data:`~mcp_kymograph.eras.STOP_REASONS`, or a local
    each assignment of which gives one on each branch. Anything else fails, naming its line;
    what this misses still fails where the ``Detection`` is made."""
    from mcp_kymograph import eras

    def allowed(node: ast.expr) -> bool:
        name = node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", None)
        if isinstance(node, ast.Attribute) and ast.unparse(node.value) != "eras":
            return False
        return name is not None and getattr(eras, name, None) in eras.STOP_REASONS

    def branches(scope: ast.AST, name: str) -> list[ast.AST]:
        """What a local is given, each branch apart. A parameter, a ``for`` target, ``+=`` and
        ``:=`` stand as themselves and are not allowed; other bindings (``with … as``,
        ``except … as``, comprehensions, ``match``) are not read here, and a reason bound so
        fails where the ``Detection`` is made."""
        found: list[ast.AST] = []
        for node in ast.walk(scope):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(_binds(target, name) for target in targets):
                    found += _branches(node.value)
            elif (isinstance(node, ast.arg) and node.arg == name) or (
                isinstance(node, (ast.AugAssign, ast.NamedExpr, ast.For))
                and _binds(node.target, name)
            ):
                found.append(node)
        return found

    tree = ast.parse(Path(eras.__file__).read_text(encoding="utf-8"))
    scopes = {
        node: function
        for function in ast.walk(tree)
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        for node in ast.walk(function)
    }
    seen, wrong = 0, []
    for call in ast.walk(tree):
        for keyword in call.keywords if isinstance(call, ast.Call) else []:
            if keyword.arg != "reason":
                continue
            seen += 1
            value, scope = keyword.value, scopes.get(call)
            given = branches(scope, value.id) if scope and isinstance(value, ast.Name) else []
            if not (all(map(allowed, given)) if given else allowed(value)):
                wrong.append(f"line {call.lineno}: reason={ast.unparse(value)}")

    assert seen and wrong == [], "eras.py: not one of STOP_REASONS: " + "; ".join(wrong)


def test_every_hint_the_store_gives_a_compared_finding_has_its_place_in_the_report():
    """``_hint`` and ``_cap_hint`` are handed each hint as a literal; the report shows only
    those of :data:`~mcp_kymograph.report.COMPARED_HINTS`, so none may be missing there."""
    tree = ast.parse((PACKAGE / "store.py").read_text(encoding="utf-8"))
    given = {
        node.args[-1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _called(node) in {"_hint", "_cap_hint"}
    }

    assert given == set(report.COMPARED_HINTS)


def test_what_waits_for_the_lead_is_still_in_the_report_s_source():
    tree = ast.parse((PACKAGE / "report.py").read_text(encoding="utf-8"))
    written = {ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.expr)}

    assert ASKED.issubset(written), ASKED - written


def test_an_imported_constant_is_read_as_the_string_it_is():
    from mcp_kymograph import engagement, store

    assert spans_not_allowed(
        "from mcp_kymograph.store import SCENARIO_DRIFT\nwords = _code(SCENARIO_DRIFT)"
    ) == [(2, store.SCENARIO_DRIFT)]
    assert engagement.REFUSALS_FILE in report.CODE_SPAN_IDENTIFIERS


def test_the_source_check_finds_a_planted_word_and_passes_certificate_and_docstrings():
    planted = 'def f():\n    """A secure docstring is not a document."""\n    return "it is safe"\n'
    passing = 'def f():\n    return f"the certificate of {name}"\n'

    assert banned_in_source(planted) == [(3, "safe")]
    assert banned_in_source(passing) == []


def test_only_the_banned_list_itself_may_spell_the_words():
    assert banned_in_source('BANNED_WORDS = ("safe", "risk")\n') == []
    assert banned_in_source('WORDS = ("safe",)\nBANNED_WORDS = ("risk",)\n') == [(1, "safe")]
    assert banned_in_source('BANNED_WORDS = ("risk",)\nlater = f"no {x} risk"\n') == [(2, "risk")]
    assert banned_in_source('BANNED_WORDS_NOTE = "the server is safe"\n') == [(1, "safe")]
    assert banned_in_source('BANNED_WORDS_DE = ("clean",)\n') == [(1, "clean")]
    assert banned_in_source('BANNED_WORDS = ("risk", "the server is secure")\n') == [
        (1, "risk"),
        (1, "secure"),
    ]
