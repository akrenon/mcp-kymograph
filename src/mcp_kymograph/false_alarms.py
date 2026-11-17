"""Measure how often each signal fires on text that is harmless: the false-alarm rate.

    python -m mcp_kymograph.false_alarms CORPUS [--format auto|lines|json|jsonl]
                                             [--examples N] [--confidence C] [--json]

A tool for whoever calibrates the signals, not a step of any run. It reads a corpus of
descriptions that are known to be harmless — tool descriptions of servers nobody suspects,
say — applies every signal of the library to each entry, and reports per signal how many
entries it fired on, the rate, a confidence interval for that rate, and the first entries it
fired on. A signal that fires on harmless text fires falsely; how often, with what certainty,
is what the declared-only signals (``imperative``, ``second_person``, ``embedded_url``, …) lack
before the walk can apply them by default.

**The corpus is the caller's.** None ships with this repository: real descriptions are other
people's text, and what they say is theirs. The tests use a few lines written for them.

The corpus file is one of:

* ``lines`` — one description per line;
* ``json`` — a JSON array of strings, or of objects with a ``description`` string;
* ``jsonl`` — one JSON string, or one such object, per line.

``auto`` (the default) picks by the file's suffix: ``.json``, ``.jsonl`` or ``.ndjson``,
anything else lines. Lines end at ``\n`` (and a ``\r`` before it) only: U+2028, U+0085, a
form feed and the like are part of a description, not breaks in it. An empty description, or
one of only whitespace, is skipped in every format. Each description keeps where it was found
(``line 4``, ``entry 3``), and examples say so.

**Bounds.** At most :data:`MAX_CORPUS_BYTES` bytes, :data:`MAX_ENTRIES` descriptions and
:data:`MAX_ENTRY_CHARS` characters in one; past any of them the corpus is refused, never
silently cut. Anything that does not read — not UTF-8, not JSON, nested too deep, the wrong
shape — is a :class:`CorpusError` naming the place, and exit status 2.

**What is reported, and what is not.** Every signal is applied to every entry on its own, the
way :func:`mcp_kymograph.signals.check` applies it to one surface — reach does not matter here,
since the point is the rate a signal would have if it were applied everywhere. The interval is
the Wilson score interval of :mod:`mcp_kymograph.rates` (two-sided, at ``--confidence``); with no
hit at all, the rule of three is reported beside it, as the design of repeated runs does —
always at 95 %, whatever ``--confidence`` says, and labelled so. A hit only in the normalised
view is counted, and counted apart (``via_normalized``). The number of distinct descriptions is
reported beside the number of all: the interval takes every description as an independent
draw, and a corpus that holds one server's description five times is not five draws.
``tool_name_duplicate`` and ``tool_name_lookalike`` compare a name with the other names of one
listing; a corpus of descriptions has no listing, and they are reported as not measured.
Nothing here decides which rate is low enough: that is for whoever reads the numbers.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_kymograph import rates
from mcp_kymograph.signals import LIBRARY, Subject, Via, View, check

#: The most bytes read from a corpus file. A corpus is a calibration set, not a dump.
MAX_CORPUS_BYTES = 16 * 1024 * 1024
#: The most descriptions in one corpus, and the longest description.
MAX_ENTRIES = 200_000
MAX_ENTRY_CHARS = 100_000
#: How many characters of an example entry are shown.
EXAMPLE_LENGTH = 200

FORMATS = ("auto", "lines", "json", "jsonl")
_SUFFIXES = {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl"}

#: Shown as an escape though not a control character: blanks that are not a space, fillers
#: and joiners that draw nothing, variation selectors.
_INVISIBLE = frozenset(
    [
        0x034F,
        0x115F,
        0x1160,
        0x2800,
        0x3164,
        0xFFA0,
        *range(0xFE00, 0xFE10),
        *range(0xE0100, 0xE01F0),
    ]
)


class CorpusError(ValueError):
    """A corpus that cannot be read as asked, with the file and the place in it."""


@dataclass(frozen=True)
class Entry:
    """One description and where in the corpus it stands."""

    text: str
    place: str


@dataclass
class Tally:
    """One signal over the corpus."""

    signal: str
    reach: str
    hits: int = 0
    via_normalized: int = 0
    examples: list[dict[str, Any]] = field(default_factory=list)


def read_corpus(path: Path, fmt: str = "auto") -> list[Entry]:
    """The descriptions of a corpus file, in order. Raises :class:`CorpusError`."""
    if fmt not in FORMATS:
        raise CorpusError(f"unknown format {fmt!r}; one of {', '.join(FORMATS)}")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_CORPUS_BYTES + 1)
    except OSError as exc:
        raise CorpusError(f"{path}: cannot read: {exc.strerror or exc}") from None
    if len(raw) > MAX_CORPUS_BYTES:
        raise CorpusError(f"{path}: larger than {MAX_CORPUS_BYTES} bytes")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CorpusError(f"{path}: not UTF-8 at byte {exc.start}") from None
    if fmt == "auto":
        fmt = _SUFFIXES.get(path.suffix.lower(), "lines")
    found: list[Entry] = []
    if fmt == "json":
        document = _loads(text, f"{path}")
        if not isinstance(document, list):
            raise CorpusError(f"{path}: a JSON corpus is an array")
        for index, item in enumerate(document):
            _keep(found, _entry(item, f"{path}: entry {index}"), f"entry {index}", path)
        return found
    for number, line in enumerate(_lines(text), start=1):
        if fmt == "jsonl" and line.strip():
            item = _loads(line, f"{path}: line {number}")
            line = _entry(item, f"{path}: line {number}")
        _keep(found, line, f"line {number}", path)
    return found


def _lines(text: str) -> list[str]:
    # A final line feed leaves an empty last line, skipped like every empty one.
    return [line.removesuffix("\r") for line in text.split("\n")]


def _loads(text: str, where: str) -> Any:
    try:
        return json.loads(text)
    except RecursionError:
        raise CorpusError(f"{where}: nested too deep") from None
    except ValueError as exc:
        raise CorpusError(f"{where}: not JSON: {exc}") from None


def _keep(found: list[Entry], text: str, place: str, path: Path) -> None:
    if not text.strip():
        return
    if len(text) > MAX_ENTRY_CHARS:
        raise CorpusError(f"{path}: {place}: longer than {MAX_ENTRY_CHARS} characters")
    if len(found) == MAX_ENTRIES:
        raise CorpusError(f"{path}: more than {MAX_ENTRIES} descriptions")
    found.append(Entry(text, place))


def _entry(item: Any, where: str) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict) and isinstance(item.get("description"), str):
        return item["description"]
    raise CorpusError(f"{where}: neither a string nor an object with a description string")


def measure(entries: Sequence[Entry | str], *, examples: int = 3) -> tuple[list[Tally], list[str]]:
    """Apply every signal to every entry. Returns the tallies, in library order, and the
    signals that were not measured (those that need a listing, not one text). A plain string
    stands at ``entry <index>``."""
    measured = [d for d in LIBRARY if d.view is not View.NAME]
    skipped = [d.signal.value for d in LIBRARY if d.view is View.NAME]
    tallies = {d.signal: Tally(d.signal.value, d.reach.value) for d in measured}
    for index, item in enumerate(entries):
        entry = item if isinstance(item, Entry) else Entry(item, f"entry {index}")
        subject = Subject(entry.text)
        for definition in measured:
            via = check(definition.signal, subject)
            if via is None:
                continue
            tally = tallies[definition.signal]
            tally.hits += 1
            if via is Via.NORMALIZED:
                tally.via_normalized += 1
            if len(tally.examples) < examples:
                tally.examples.append(
                    {"place": entry.place, "via": via.value, "text": shown(entry.text)}
                )
    return list(tallies.values()), skipped


def report(
    entries: Sequence[Entry | str],
    tallies: Iterable[Tally],
    skipped: Iterable[str],
    *,
    confidence: float = rates.CONFIDENCE,
) -> dict[str, Any]:
    """The measurement as a JSON-ready document."""
    n = len(entries)
    texts = {item.text if isinstance(item, Entry) else item for item in entries}
    signals = []
    for tally in tallies:
        interval = rates.wilson(tally.hits, n, confidence=confidence)
        signals.append(
            {
                "signal": tally.signal,
                "reach": tally.reach,
                "hits": tally.hits,
                "via_normalized": tally.via_normalized,
                "rate": tally.hits / n if n else None,
                "interval": {"lower": interval.lower, "upper": interval.upper},
                "rule_of_three_95": rates.rule_of_three(n) if n and not tally.hits else None,
                "examples": tally.examples,
            }
        )
    return {
        "entries": n,
        "distinct": len(texts),
        "confidence": confidence,
        "interval": "wilson",
        "signals": signals,
        "not_measured": [
            {"signal": signal, "why": "compares names within one listing"} for signal in skipped
        ],
    }


def shown(text: str, limit: int = EXAMPLE_LENGTH) -> str:
    """An entry as it can be printed on one line: cut to ``limit`` characters of the entry,
    then every control, format, separator, private, unassigned or otherwise invisible
    character written as ``\\u{hex}``, and a backslash as two — so the escape of a character
    and the same text typed out never look alike."""
    cut = len(text) > limit
    out = []
    for character in text[: max(limit, 1) - 1] if cut else text:
        if character == "\\":
            out.append("\\\\")
        elif _invisible(character):
            out.append(f"\\u{{{ord(character):x}}}")
        else:
            out.append(character)
    return "".join(out) + ("…" if cut else "")


def _invisible(character: str) -> bool:
    category = unicodedata.category(character)
    if category in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
        return True
    if category == "Zs":
        return character != " "
    return ord(character) in _INVISIBLE


def _percent(value: float) -> str:
    """A rate with three significant digits, so a small one does not round to nothing."""
    return f"{value * 100:.3g} %"


def table(document: dict[str, Any]) -> str:
    """The measurement for a person: one line per signal, examples below."""
    level = f"{document['confidence'] * 100:g} %"
    lines = [
        f"{document['entries']} entries ({document['distinct']} distinct); "
        f"interval: Wilson, {level}",
        "",
    ]
    lines.append(f"{'signal':<24}{'reach':<12}{'hits':>7}{'rate':>11}   interval")
    for row in document["signals"]:
        rate = "-" if row["rate"] is None else _percent(row["rate"])
        interval = f"{_percent(row['interval']['lower'])} to {_percent(row['interval']['upper'])}"
        if row["rule_of_three_95"] is not None:
            interval += f"  (rule of three, 95 %: < {_percent(row['rule_of_three_95'])})"
        lines.append(
            f"{row['signal']:<24}{row['reach']:<12}{row['hits']:>7}{rate:>11}   {interval}"
        )
    for row in document["signals"]:
        for example in row["examples"]:
            lines.append(
                f"  {row['signal']}, {example['place']} ({example['via']}): {example['text']}"
            )
    for row in document["not_measured"]:
        lines.append(f"not measured: {row['signal']} ({row['why']})")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m mcp_kymograph.false_alarms",
        description="How often each signal fires on harmless descriptions.",
    )
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--format", default="auto", choices=FORMATS)
    parser.add_argument("--examples", type=int, default=3, metavar="N")
    parser.add_argument("--confidence", type=float, default=rates.CONFIDENCE, metavar="C")
    parser.add_argument("--json", action="store_true", help="the report as JSON on stdout")
    args = parser.parse_args(argv)
    if args.examples < 0:
        parser.error("--examples must not be negative")
    if not 0 < args.confidence < 1:
        parser.error("--confidence must lie strictly between 0 and 1")
    try:
        entries = read_corpus(args.corpus, args.format)
    except CorpusError as refusal:
        print(f"false_alarms: {refusal}", file=sys.stderr)
        return 2
    tallies, skipped = measure(entries, examples=args.examples)
    document = report(entries, tallies, skipped, confidence=args.confidence)
    text = json.dumps(document, indent=2) if args.json else table(document)
    if isinstance(sys.stdout, io.TextIOWrapper):
        # A terminal or pipe that cannot write a character gets its escape, not a traceback.
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        print(text, flush=True)
    except BrokenPipeError:
        # The reader went away (``| head``): what it did not read is not ours to report, and
        # the interpreter's own flush at exit must not fail on the closed pipe either.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
