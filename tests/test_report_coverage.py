"""The coverage statement.

Each clause is present exactly when the recorded fact it names holds, every clause is
``derived``, and the report's section 7 and the attestation carry the same clauses for the same
store. :func:`report.coverage` is held against every combination of its facts;
:func:`report.coverage_facts` against the store's chain, runs and recordings; and both documents
against one engagement made as an operator makes it (tests/fixtures/customer_engagement.py).
"""

import dataclasses
import itertools
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from mcp_kymograph import report, verdict

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import customer_engagement  # noqa: E402

NOW = datetime.now(timezone.utc).replace(microsecond=0)

#: Each clause by words only it has.
CLAUSES = {
    "no_tool_called": "This engagement's runs called no tool",
    "client_not_observed": "how a client reacts to the text the server hands it",
    "egress_not_observed": "This engagement did not observe egress",
    "server_not_run": "This engagement did not run the server",
    "observation": "This engagement's observations say where something sat",
    "recordings_beside": "this attestation does not read such recordings",
}
#: The clauses of a document without recordings beside the store's runs.
WITHOUT_SESSIONS = set(CLAUSES) - {"recordings_beside"}


def clauses(sentences) -> set[str]:
    found = [name for s in sentences for name, words in CLAUSES.items() if words in s.words]
    assert len(found) == len(set(found)), found
    return set(found)


def facts(**changes) -> report.Coverage:
    values = {
        "calls_declared_false": True,
        "recordings_read": 2,
        "recordings_unread": 0,
        "step_called": 0,
        "script_called": 0,
        "isolations": {"host": 2},
        "sessions": None,
    }
    values.update(changes)
    return report.Coverage(**values)


# -- the clauses, against their facts ---------------------------------------------------------

#: The facts of "called no tool": all hold, or one of them does not.
CALLS = [
    {},
    {"calls_declared_false": False},
    {"recordings_read": 0},
    {"recordings_unread": 1},
    {"step_called": 1},
    {"script_called": 2},
]
ISOLATIONS = [{}, {"host": 2}, {"runc": 2}, {"remote": 1}, {"host": 1, "remote": 1, "runc": 3}]
SESSIONS = [None, 0, 1]


@pytest.mark.parametrize(
    ("calls", "isolations", "sessions"), list(itertools.product(CALLS, ISOLATIONS, SESSIONS))
)
def test_each_clause_is_present_exactly_when_its_fact_holds(calls, isolations, sessions):
    given = facts(**calls, isolations=isolations, sessions=sessions)

    expected = {"observation"}
    if not calls:
        expected.add("no_tool_called")
    if sessions in (None, 0):
        expected.add("client_not_observed")
    else:
        expected.add("recordings_beside")
    if set(isolations) - set(verdict.OBSERVED_ISOLATIONS):
        expected.add("egress_not_observed")
    if "remote" in isolations:
        expected.add("server_not_run")
    assert clauses(report.coverage(given)) == expected


@pytest.mark.parametrize("sessions", [None, 0, 2])
def test_every_clause_is_derived_begins_with_this_engagement_and_is_a_line_a_report_holds(
    sessions,
):
    sentences = report.coverage(facts(isolations={"host": 1, "remote": 2}, sessions=sessions))

    assert len(sentences) == len(WITHOUT_SESSIONS)
    for sentence in sentences:
        assert sentence.kind == report.DERIVED
        assert sentence.words.startswith("This engagement")
        assert "witnessed" not in sentence.text.lower()
        assert "assessment" not in sentence.text.lower()
        assert not customer_engagement.banned_in(sentence.text)
        assert report._parse_item(sentence.line(), 1, report.ATTESTATION_KINDS) == sentence


def test_the_last_clause_is_the_readme_s_rule_and_always_there():
    for given in (facts(), facts(calls_declared_false=False, isolations={}, sessions=3)):
        last = report.coverage(given)[-1]
        assert "where something sat and what shape it had, not whether it has an effect" in (
            last.words
        )


def test_the_report_s_client_clause_names_its_reason_and_the_attestation_s_names_the_index():
    (of_report,) = [s for s in report.coverage(facts(sessions=None)) if "client" in s.words]
    (of_bundle,) = [s for s in report.coverage(facts(sessions=0)) if "client" in s.words]

    assert of_report.values == ("engagement report", "--session")
    assert of_report.words.startswith("This engagement's report does not show")
    assert of_bundle.values == ("filed: false",)
    assert "the bundle's index lists no recording of a client session" in of_bundle.words
    for sentence in (of_report, of_bundle):
        assert "each driven by this tool in the client's place" in sentence.words
        assert "script" not in sentence.words


@pytest.mark.parametrize(
    ("count", "words"), [(1, "1 recording beside"), (3, "3 recordings beside")]
)
def test_recordings_beside_the_runs_are_said_and_not_read_as_client_sessions(count, words):
    sentences = report.coverage(facts(sessions=count))

    (beside,) = [s for s in sentences if "beside the store's runs" in s.words]
    assert beside.kind == report.DERIVED
    assert beside.words.startswith(f"This engagement's bundle lists {words} the store's runs")
    assert beside.values == ("filed: false",)
    assert "does not read such recordings" in beside.words
    assert "is not said here" in beside.words
    assert not [s for s in sentences if "did not observe how a client" in s.words]


def test_egress_is_named_by_isolation_with_its_count_and_never_for_an_observed_one():
    given = facts(isolations={"host": 2, "remote": 1, "runc": 4})

    (egress,) = [s for s in report.coverage(given) if "egress" in s.words]
    assert "2 runs with isolation `host` and 1 run with isolation `remote`:" in egress.text
    assert "with isolation `runc`" not in egress.text
    assert ", ".join(verdict.OBSERVED_ISOLATIONS) in egress.values
    (remote,) = [s for s in report.coverage(given) if "did not run the server" in s.words]
    assert "in 1 of its 7 runs" in remote.words


def test_no_tool_called_counts_the_recordings_read():
    (one,) = [s for s in report.coverage(facts(recordings_read=1)) if "no tool" in s.words]
    (three,) = [s for s in report.coverage(facts(recordings_read=3)) if "no tool" in s.words]

    assert "none of the 1 recording read" in one.words
    assert "none of the 3 recordings read" in three.words
    assert three.values == ("actions.call: false", "step_called", "script_finished")


# -- the facts, from the chain, the runs and the recordings -----------------------------------


def chain(*calls) -> list[dict]:
    return [{"file_declared": {"actions": {"list": True, "call": call}}} for call in calls]


def runs_and_recordings(*recordings: report._Recording, isolation: str = "host"):
    runs = [SimpleNamespace(run=f"r{i}", isolation=isolation) for i in range(len(recordings))]
    return runs, {run.run: recording for run, recording in zip(runs, recordings, strict=True)}


def test_actions_call_false_must_hold_in_every_version_of_the_chain():
    runs, recordings = runs_and_recordings(report._Recording("read"))

    assert report.coverage_facts(chain(False, False), runs, recordings, None).calls_declared_false
    for versions in (chain(True, False), chain(False, True), chain(None), []):
        held = report.coverage_facts(versions, runs, recordings, None)
        assert not held.calls_declared_false, versions
    no_actions = [{"file_declared": {}}]
    assert not report.coverage_facts(no_actions, runs, recordings, None).calls_declared_false


def test_the_facts_count_what_the_recordings_read_hold_and_the_runs_by_isolation():
    runs, recordings = runs_and_recordings(
        report._Recording("read", calls=2),
        report._Recording("read", script_called=1),
        report._Recording("not_found", "not found under the runs directory", calls=5),
    )
    runs[2].isolation = "remote"

    held = report.coverage_facts(chain(False), runs, recordings, sessions=4)

    assert held == report.Coverage(
        calls_declared_false=True, recordings_read=2, recordings_unread=1, step_called=2,
        script_called=1, isolations={"host": 2, "remote": 1}, sessions=4,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("events", "count"),
    [
        ([], 0),
        ([{"type": "script_finished", "inventory": "complete"}], 0),
        ([{"type": "script_finished", "called": []}], 0),
        ([{"type": "script_finished", "called": ["a", "b"]}], 2),
        ([{"type": "script_finished", "called": None}], 1),
        ([{"type": "step_called", "called": ["a"]}], 0),
        ([{"type": "script_finished", "called": ["a"]}] * 2, 2),
    ],
)
def test_script_finished_called_is_counted_where_present(events, count):
    assert report._script_called(events) == count


# -- the documents ----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def made(tmp_path_factory):
    return customer_engagement.make(tmp_path_factory.mktemp("coverage"), NOW)


def opening(items) -> list[report.Sentence]:
    """The sentences before the first heading."""
    taken = []
    for item in items:
        if isinstance(item, report.Heading):
            break
        taken.append(item)
    return taken


def paragraph(items, heading: str) -> list[report.Sentence]:
    start = items.index(report.Heading(heading))
    return opening(items[start + 1 :])


ATTESTATION_HEADING = "What this engagement did not do or observe"


def test_the_report_s_section_7_opens_with_the_coverage_paragraph(made):
    seven = report.parse(made.report).sections[6]

    first = opening(seven.items)
    assert clauses(first) == WITHOUT_SESSIONS
    assert len(first) == len(WITHOUT_SESSIONS)
    assert all(s.kind == report.DERIVED for s in first)
    assert report.Heading("What a finding says") in seven.items


def test_the_attestation_carries_the_same_clauses_as_the_report(made):
    seven = report.parse(made.report).sections[6]
    attested = report.parse_attestation(made.attestation)

    assert clauses(paragraph(attested.items, ATTESTATION_HEADING)) == clauses(opening(seven.items))


def test_a_recording_beside_the_store_s_runs_is_said_in_place_of_the_client_clause(made):
    attested = report.parse_attestation(made.attestation_with_session)

    assert clauses(paragraph(attested.items, ATTESTATION_HEADING)) == set(CLAUSES) - {
        "client_not_observed"
    }


def test_a_recording_not_read_drops_the_no_tool_clause(made, tmp_path):
    runs = tmp_path / "runs"
    shutil.copytree(made.runs, runs)
    next(runs.rglob("events.jsonl")).unlink()

    built = report.build(engagement_path=made.held, store=made.database, runs_dir=runs, now=NOW)

    seven = report.parse(report.render(built)).sections[6]
    assert clauses(opening(seven.items)) == WITHOUT_SESSIONS - {"no_tool_called"}


def test_a_tool_call_in_a_recording_drops_the_no_tool_clause_from_both(made, monkeypatch):
    found = report._read_recordings
    for change in ({"calls": 1}, {"script_called": 1}):

        def calling(store, runs, runs_dir, change=change):
            read = found(store, runs, runs_dir)
            first = min(read)
            return {**read, first: dataclasses.replace(read[first], **change)}

        monkeypatch.setattr(report, "_read_recordings", calling)
        built = report.build(
            engagement_path=made.held, store=made.database, runs_dir=made.runs, now=NOW
        )
        attested = report.attest(
            store=made.database, engagement_path=made.held, bundle_dir=made.bundle,
            runs_dir=made.runs, now=NOW,
        )  # fmt: skip

        seven = report.parse(report.render(built)).sections[6]
        expected = WITHOUT_SESSIONS - {"no_tool_called"}
        assert clauses(opening(seven.items)) == expected, change
        assert clauses(paragraph(attested.items, ATTESTATION_HEADING)) == expected, change
