"""The customer walk-through: the documents a customer receives, in order.

One engagement, made as an operator makes it against fixture servers only — host runs and an
endpoint run over loopback (tests/fixtures/customer_engagement.py) — and the documents the
customer receives, step by step, in the order the customer receives them:

- brief and traffic sheet before the window opens
- trial run against a staging target
- customer status each week
- report with the coverage paragraph and a reference link per finding
- summary after pack
- export opened in a spreadsheet
- the German set
- PDF of report and summary
- purge, receipt to the handover location

Of these steps this file holds the report; and no document of the walk-through says "witnessed".
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_kymograph import cli, report, verdict
from mcp_kymograph.signals import Signal
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

from customer_engagement import banned_in, make, sentence_words  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)


@pytest.fixture(scope="module")
def made(tmp_path_factory):
    return make(tmp_path_factory.mktemp("walkthrough"), NOW)


def sentences_before_the_first_heading(items) -> list[report.Sentence]:
    taken = []
    for item in items:
        if isinstance(item, report.Heading):
            break
        taken.append(item)
    return taken


# -- the report ------------------------------------------------------------------------------


def test_the_report_parses_into_its_seven_sections(made):
    parsed = report.parse(made.report)

    assert [section.title for section in parsed.sections] == list(report.SECTION_TITLES)


def test_the_report_opens_section_7_with_the_clauses_its_facts_imply(made):
    with Store.open_read_only(made.database) as store:
        held = store.engagement()
        isolations = {run.isolation for run in store.runs()}
    calls = {entry["file_declared"]["actions"]["call"] for entry in held["chain"]}
    seven = report.parse(made.report).sections[6]

    paragraph = sentences_before_the_first_heading(seven.items)

    assert calls == {False} and isolations == {"host", "remote"}
    assert all(s.kind == report.DERIVED for s in paragraph)
    assert paragraph[0].words.startswith("This engagement's runs called no tool")
    assert paragraph[1].words.startswith("This engagement's report does not show how a client")
    (egress,) = [s for s in paragraph if "did not observe egress" in s.words]
    assert {"host", "remote"} <= set(egress.values)
    assert not set(verdict.OBSERVED_ISOLATIONS) & isolations
    (remote,) = [s for s in paragraph if "did not run the server" in s.words]
    assert "remote" in remote.values
    assert paragraph[-1].words.startswith("This engagement's observations say where something sat")
    assert len(paragraph) == 5


def test_every_finding_names_its_reference_page(made):
    with Store.open_read_only(made.database) as store:
        keys = [
            key for provenance in ("reference", "poison", "real-world")
            for key in store.findings_by_provenance(provenance)
        ]  # fmt: skip
    parsed = report.parse(made.report)
    assert keys

    for key in keys:
        assert key["signal"] in {signal.value for signal in Signal}
        shown = [
            sentences[i + 2]
            for section in parsed.sections[2:4]
            for sentences in [section.sentences]
            for i, sentence in enumerate(sentences)
            if key["locator"] in sentence.values and key["signal"] in sentence.values
        ]
        assert shown, key
        for reference in shown:
            assert reference.kind == report.DERIVED
            assert reference.values == (f"reference/{key['signal']}.md",)
            assert "reference page, by signal id" in reference.words.lower()


def test_the_report_has_no_banned_word(made):
    assert not banned_in(sentence_words(made.report))


def documents(made) -> dict[str, str]:
    """Every document of the walk-through so far, by name."""
    texts = {
        "report.md": made.report,
        "attestation": made.attestation,
        "attestation with a recording beside the runs": made.attestation_with_session,
        "status": made.status,
        "redactions.json": made.redactions,
        "purged.json": made.purged,
    }
    texts.update({f"CUSTOMER-README.md v{v}": text for v, text in made.readmes.items()})
    for where in (made.bundle, made.handover):
        for page in sorted((where / "reference").glob("*.md")):
            texts[f"{where.name}/reference/{page.name}"] = page.read_text(encoding="utf-8")
    return texts


def test_no_document_of_the_walk_through_says_witnessed(made):
    """Nothing records that a customer watched a run."""
    texts = documents(made)

    assert any(name.endswith(".md") and "/reference/" in name for name in texts)
    for name, text in texts.items():
        assert not re.search(r"(?<!\w)witness", text, re.IGNORECASE), name


def subcommand(parser: argparse.ArgumentParser, *names: str) -> argparse.ArgumentParser:
    """The parser of a subcommand, by the names typed to reach it."""
    for name in names:
        (choices,) = [
            action.choices
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        parser = choices[name]
    return parser


def test_the_help_of_evidence_pack_does_not_say_witnessed():
    """``--session`` names a recording a customer watched; its help does not call it witnessed."""
    text = subcommand(cli.build_parser(), "evidence", "pack").format_help()

    assert "--session" in text
    assert not re.search(r"witness", text, re.IGNORECASE)
