"""``CUSTOMER-README.md``: the one page that goes with a handover bundle.

The same text for every customer; only names and numbers differ. Every name and number stands
on a line of its own as a JSON value, so that :func:`parse_customer_readme` reads back exactly
what :func:`render_customer_readme` was given, whatever characters a name holds, and a name can
neither break the page's layout nor pass for a line of the fixed text.

The page names its bundle's index digest, so it cannot be listed in that index — a file the
index lists is part of what the digest is over. It lies beside ``index.json`` as the signature
does, and :func:`mcp_kymograph.evidence.verify` checks the one thing it can: that the digest
the page names is the index's.

**A page version.** :func:`mcp_kymograph.evidence.verify` rebuilds the page byte for byte, so
a changed sentence would fail every bundle made before it. The wording therefore has a version
(:data:`WORDINGS`, :data:`PAGE_VERSION`): a handover bundle's index names the version its page
was made with (``page_version``), and the page is rebuilt with that wording. A new wording is a
new entry under the next number, never an edit of an entry: a bundle names a wording, and the
wording it names stays as it was. Version 1 is the first: the wording of 2026-11-09, which
dropped the sentences that used a word the generated documents do not use. It names the tool and
its command as they were called then, and keeps doing so: a bundle made with it is checked against
it. Version 2 is the wording since the tool is called Kymograph: the two lines under "Checking it"
that name the tool and the command differ, nothing else.

Nothing here reads or writes a file.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

CUSTOMER_README = "CUSTOMER-README.md"

#: The names and numbers, in the order the page lists them, with the words before each.
_FIELDS = (
    ("engagement_id_declared", "Engagement (as declared)"),
    ("customer_declared", "Customer (as declared)"),
    ("window_from", "Window from (UTC)"),
    ("window_until", "Window until (UTC)"),
    ("index_digest", "Index digest (SHA-256 of index.json)"),
    ("derived_from", "Derived from the bundle with index digest"),
    ("created_utc", "Made (UTC)"),
    ("recordings", "Recordings"),
    ("egress_not_observed", "Recordings with egress not observed"),
    ("redaction_rules", "Redaction rules applied for this handover"),
    ("values_redacted", "Values redacted for this handover"),
    ("report", "Report included"),
)

_LINE = re.compile(r"- (?P<words>[^:\n]+): (?P<value>.+)")


@dataclass(frozen=True, slots=True)
class ReadmeFields:
    """What a customer README names: everything else on the page is fixed text."""

    engagement_id_declared: str
    customer_declared: str | None
    window_from: str | None
    window_until: str | None
    index_digest: str
    derived_from: str | None
    created_utc: str
    recordings: int
    egress_not_observed: int
    redaction_rules: int
    values_redacted: int
    report: bool

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name, _ in _FIELDS}


@dataclass(frozen=True, slots=True)
class Wording:
    """One version of the page's words: the words before each name and number, in the order
    the page lists them, and the fixed text around them, with ``{listed}`` where the names and
    numbers stand and ``{index_digest}`` in the command that checks the bundle."""

    labels: tuple[tuple[str, str], ...]
    text: str


_PAGE_1 = """# Evidence bundle

This directory is the evidence of one engagement, handed over by the operator who made it.
It holds what was recorded — the recordings of every run, the scenarios and the corpus
manifest the runs were made with, the engagement file the runs were checked against (without
contacts, references and the operator's redaction patterns), and the refusals the tool wrote
down — and `index.json`, which lists every file with its SHA-256, its size and what it is.

{listed}

## Checking it

With mcp-polygraph installed, run:

    mcp-polygraph evidence verify DIR --index-digest {index_digest}

where DIR is this directory. It recomputes the digest of every file the index lists and says
of each whether it is intact, changed or missing, and names any file the index does not list.
The bundle is intact only when every file is. Compare the index digest above with the one the
operator gave you by another way: this page lies beside the index and is not covered by it, so
it cannot vouch for itself. The check needs nothing but this directory and the tool; it does
not need the operator's store.

## What was done to the recordings

Every recording was masked when it was written: what looked like a credential was replaced
before it reached the disk. For this handover the recordings were redacted once more, with the
number of rules named above, which the operator agreed with you; the rules themselves are not
named here, and `redactions.json` lists each place a value was blanked and which rule did it,
never the value. A redacted recording differs from the one first filed, so its entry in the
index names the digest of the original, and the operator's store is not included.

## What "egress not observed" means

A run is marked so when the server ran on the operator's machine without the sandbox that
records what it sends out, or ran elsewhere and was reached over the network. Whatever such a
server sent anywhere but back to the tool was not seen; the recording says nothing about it,
in either direction.

## What this is not

Nothing in this bundle is a verdict. A finding is a fact about what a server sent — which
signal, on which surface — not a judgement of the server; the judgement of each finding is a
person's, recorded apart with that person's name. A finding against a server someone else
runs (real-world) is a candidate for responsible disclosure, never a confirmed weakness.
"""

_PAGE_2 = """# Evidence bundle

This directory is the evidence of one engagement, handed over by the operator who made it.
It holds what was recorded — the recordings of every run, the scenarios and the corpus
manifest the runs were made with, the engagement file the runs were checked against (without
contacts, references and the operator's redaction patterns), and the refusals the tool wrote
down — and `index.json`, which lists every file with its SHA-256, its size and what it is.

{listed}

## Checking it

With Kymograph installed, run:

    kymograph evidence verify DIR --index-digest {index_digest}

where DIR is this directory. It recomputes the digest of every file the index lists and says
of each whether it is intact, changed or missing, and names any file the index does not list.
The bundle is intact only when every file is. Compare the index digest above with the one the
operator gave you by another way: this page lies beside the index and is not covered by it, so
it cannot vouch for itself. The check needs nothing but this directory and the tool; it does
not need the operator's store.

## What was done to the recordings

Every recording was masked when it was written: what looked like a credential was replaced
before it reached the disk. For this handover the recordings were redacted once more, with the
number of rules named above, which the operator agreed with you; the rules themselves are not
named here, and `redactions.json` lists each place a value was blanked and which rule did it,
never the value. A redacted recording differs from the one first filed, so its entry in the
index names the digest of the original, and the operator's store is not included.

## What "egress not observed" means

A run is marked so when the server ran on the operator's machine without the sandbox that
records what it sends out, or ran elsewhere and was reached over the network. Whatever such a
server sent anywhere but back to the tool was not seen; the recording says nothing about it,
in either direction.

## What this is not

Nothing in this bundle is a verdict. A finding is a fact about what a server sent — which
signal, on which surface — not a judgement of the server; the judgement of each finding is a
person's, recorded apart with that person's name. A finding against a server someone else
runs (real-world) is a candidate for responsible disclosure, never a confirmed weakness.
"""

#: Every wording of the page, by page version. Entries are added, never changed.
WORDINGS: Mapping[int, Wording] = MappingProxyType(
    {1: Wording(_FIELDS, _PAGE_1), 2: Wording(_FIELDS, _PAGE_2)}
)
#: The version a page is made with now.
PAGE_VERSION = 2


def wording(version: int) -> Wording:
    """The wording of ``version``; :class:`ValueError` for a version this tool does not know."""
    if type(version) is not int or version not in WORDINGS:
        known = ", ".join(str(number) for number in sorted(WORDINGS))
        raise ValueError(f"page version {version!r} is not one this tool knows ({known})")
    return WORDINGS[version]


def render_customer_readme(fields: ReadmeFields, version: int | None = None) -> str:
    """The page, from names and numbers only, in the wording of ``version`` (by default
    :data:`PAGE_VERSION`)."""
    chosen = wording(PAGE_VERSION if version is None else version)
    listed = "\n".join(
        f"- {words}: {json.dumps(getattr(fields, name), ensure_ascii=True)}"
        for name, words in chosen.labels
    )
    return chosen.text.format(listed=listed, index_digest=fields.index_digest)


def parse_customer_readme(text: str, version: int | None = None) -> ReadmeFields:
    """The names and numbers of a page :func:`render_customer_readme` wrote in the wording of
    ``version`` (by default :data:`PAGE_VERSION`), read whole or refused whole with
    :class:`ValueError`: every field once, each of its type."""
    labels = wording(PAGE_VERSION if version is None else version).labels
    values: dict[str, Any] = {}
    names = {words: name for name, words in labels}
    for line in text.splitlines():
        match = _LINE.fullmatch(line)
        if match is None or match["words"] not in names:
            continue
        name = names[match["words"]]
        if name in values:
            raise ValueError(f"{match['words']} is named twice")
        try:
            values[name] = json.loads(match["value"])
        except ValueError:
            raise ValueError(f"{match['words']}: not a JSON value") from None
    missing = [words for name, words in labels if name not in values]
    if missing:
        raise ValueError(f"not a customer README: {', '.join(missing)} not named")
    for name in ("engagement_id_declared", "index_digest", "created_utc"):
        if not isinstance(values[name], str):
            raise ValueError(f"{name}: expected a string")
    for name in ("customer_declared", "window_from", "window_until", "derived_from"):
        if values[name] is not None and not isinstance(values[name], str):
            raise ValueError(f"{name}: expected a string or null")
    for name in ("recordings", "egress_not_observed", "redaction_rules", "values_redacted"):
        if type(values[name]) is not int or values[name] < 0:
            raise ValueError(f"{name}: expected a count")
    if not isinstance(values["report"], bool):
        raise ValueError("report: expected true or false")
    return ReadmeFields(**values)
