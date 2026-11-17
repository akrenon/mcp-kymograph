"""The finding store: filed by key, compared run against run, never deciding what a finding is."""

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import __version__, cli, verdict
from mcp_kymograph.events import SCHEMA_VERSION as RECORDING_SCHEMA
from mcp_kymograph.store import (
    KEY_FIELDS,
    SCENARIO_DRIFT,
    Ingested,
    Store,
    StoreError,
    canonical_key,
    ingest_all,
)

FIXTURES = Path(__file__).parent / "fixtures"
DISCOVERY = FIXTURES / "discovery_server.py"
POISON = FIXTURES / "corpus" / "poison_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"

VERSION = "sha256:" + "aa" * 32
TOOL_CONTENT = "sha256:" + "11" * 32
LAUNCH = "sha256:" + "22" * 32
SCENARIO_DIGEST = "d" * 64
LOCATOR = 'result.tools[name="w"].description'


# -- synthetic corpus recordings ------------------------------------------------------------


def key(**changes):
    base = {
        "server": "srv",
        "server_version": VERSION,
        "tool_version": __version__,
        "scenario": "scn",
        "statement": "st",
        "locator": LOCATOR,
        "signal": "hidden_comment",
    }
    return {**base, **changes}


def finding(seq, path="result.tools[0].description", **changes):
    return {
        "seq": seq,
        "type": "finding",
        "key": key(**changes),
        "direction": "server_to_client",
        "method": "tools/list",
        "message_seq": 4,
        "path": path,
        "normalized": False,
    }


def recording(
    tmp_path,
    findings,
    *,
    name="run",
    mode="driver",
    triple=True,
    finished=True,
    script=True,
    counts=None,
    asked=(),
    provenance="poison",
    entry="srv",
    version=VERSION,
    tool=__version__,
    tool_content=TOOL_CONTENT,
    launch=LAUNCH,
    scenario_digest=SCENARIO_DIGEST,
    isolation="host",
    sandbox_image=None,
    target_image=None,
    extra=(),
    schema=RECORDING_SCHEMA,
):
    """A corpus recording with these findings, counted honestly unless told otherwise.

    ``asked`` adds (statement, signal) pairs the scenario asked for and nothing fired on.
    """
    if counts is None:
        counts = {}
        for event in findings:
            if isinstance(event, dict) and event.get("type") == "finding":
                k = event["key"]
                counts.setdefault(k["statement"], {}).setdefault(k["signal"], 0)
                counts[k["statement"]][k["signal"]] += 1
        for statement, signal in asked:
            counts.setdefault(statement, {}).setdefault(signal, 0)
    reproduction = {
        "manifest": {"source": "m.yaml", "digest": "sha256:" + "33" * 32},
        "corpus": {
            "entry": entry,
            "provenance": provenance,
            "identity": {"kind": "content", "version": version, "files": 1},
            "launch_digest": launch,
        },
        "tool": {"version": tool, "content": tool_content},
        "scenario": {"name": "scn", "digest": scenario_digest},
        "environment": {
            "isolation": isolation,
            "sandbox_image": sandbox_image,
            "target_image": target_image,
        },
    }
    events = [
        {
            "run_id": "abcd1234",
            "seq": 1,
            "type": "run_started",
            "mode": mode,
            "tool_version": tool,
            "scenario_name": "scn",
            "server_name": entry,
            "server_identity": {"kind": "content", "version": version, "files": 1},
            "reproduction": reproduction if triple else None,
            "authorization": {"scenario_digest": scenario_digest},
            "wall_clock_utc": "2026-10-04T12:00:00.000+00:00",
            "isolation": isolation,
            "schema_version": schema,
        },
        *findings,
        *extra,
    ]
    if script:
        events.append({"seq": 98, "type": "script_finished", "inventory": "complete"})
    if finished:
        events.append(
            {
                "seq": 99,
                "type": "run_finished",
                "findings_by_statement": counts,
                "announced_server": "srv-announced",
                "server_output_bytes": 100,
                "client_input_bytes": 100,
                "server_exited_first": False,
            }
        )
    for event in events:
        if isinstance(event, dict):
            event.setdefault("v", schema)
    path = tmp_path / f"{name}.jsonl"
    path.write_text("\n".join(e if isinstance(e, str) else json.dumps(e) for e in events) + "\n")
    return path


@pytest.fixture
def store(tmp_path):
    with Store.open(tmp_path / "findings.sqlite") as opened:
        yield opened


def compare(store, before, after):
    store.ingest(before)
    store.ingest(after)
    return store.diff(store.resolve(str(before)), store.resolve(str(after)))


# -- the key -------------------------------------------------------------------------------


def test_a_finding_is_filed_under_its_seven_fields_and_its_position_is_not_among_them():
    assert KEY_FIELDS == (
        "server",
        "server_version",
        "tool_version",
        "scenario",
        "statement",
        "locator",
        "signal",
    )
    filed = canonical_key(key())
    assert "result.tools[0]" not in filed
    assert json.loads(filed) == [key()[name] for name in KEY_FIELDS]


def test_the_same_finding_at_two_positions_is_one_finding_sighted_twice(store, tmp_path):
    """Two tools sharing a name: one key, two places. The store keeps both places."""
    path = recording(
        tmp_path,
        [finding(5, "result.tools[0].description"), finding(6, "result.tools[1].description")],
    )
    store.ingest(path)
    (entry,) = store.findings_of(store.resolve(str(path))).values()
    filed_key, sightings = entry
    assert filed_key == key()
    assert [s.path for s in sightings] == [
        "result.tools[0].description",
        "result.tools[1].description",
    ]


def test_every_field_of_the_key_separates_findings(store, tmp_path):
    """Change any field a run can vary and it is another finding."""
    changes = {
        "statement": "other",
        "locator": 'result.tools[name="x"].description',
        "signal": "imperative",
    }
    events = [finding(10, **{name: value}) for name, value in changes.items()]
    events.append(finding(20))
    path = recording(tmp_path, events)
    store.ingest(path)
    assert len(store.findings_of(store.resolve(str(path)))) == len(changes) + 1


# -- filing --------------------------------------------------------------------------------


def test_the_provenance_comes_from_the_manifest_entry_the_run_recorded(store, tmp_path):
    filed = store.ingest(recording(tmp_path, [finding(5)], provenance="reference"))
    assert filed.provenance == "reference"
    assert [k["server"] for k in store.findings_by_provenance("reference")] == ["srv"]


def test_a_provenance_given_at_filing_is_a_cross_check_never_a_relabel(store, tmp_path):
    path = recording(tmp_path, [finding(5)], provenance="real-world")
    with pytest.raises(StoreError, match="refusing rather than relabelling"):
        store.ingest(path, "reference")
    assert store.runs() == []
    assert store.ingest(path, "real-world").provenance == "real-world"


def test_filing_the_same_recording_twice_files_it_once(store, tmp_path):
    path = recording(tmp_path, [finding(5)])
    first = store.ingest(path)
    again = store.ingest(path)
    assert (first.already, again.already) == (False, True)
    assert again.run == first.run
    assert len(store.runs()) == 1


@pytest.mark.parametrize(
    ("variant", "fragment"),
    [
        ({"mode": "proxy"}, "driver runs only"),
        ({"triple": False}, "--manifest"),
        ({"provenance": "trusted"}, "unknown provenance"),
    ],
)
def test_runs_the_store_cannot_compare_are_refused(store, tmp_path, variant, fragment):
    with pytest.raises(StoreError, match=fragment):
        store.ingest(recording(tmp_path, [finding(5)], **variant))
    assert store.runs() == []


def test_a_triple_that_contradicts_run_started_is_refused(store, tmp_path):
    path = recording(tmp_path, [finding(5)])
    events = [json.loads(line) for line in path.read_text().splitlines()]
    events[0]["server_name"] = "someone-else"
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    with pytest.raises(StoreError, match="triple's server differs"):
        store.ingest(path)


def test_a_recording_without_run_started_is_refused(store, tmp_path):
    path = tmp_path / "headless.jsonl"
    path.write_text(json.dumps(finding(5)) + "\n")
    with pytest.raises(StoreError, match="run_started"):
        store.ingest(path)


def test_one_finding_cannot_be_both_reference_and_real_world(store, tmp_path):
    """One of the two labels is wrong; filing both would hide a disclosure candidate among
    expected findings. The second run is refused whole — nothing of it remains."""
    store.ingest(recording(tmp_path, [finding(5)], name="a", provenance="reference"))
    second = recording(
        tmp_path, [finding(5), finding(6, locator="x")], name="b", provenance="real-world"
    )
    with pytest.raises(StoreError, match="already filed as 'reference'"):
        store.ingest(second)
    assert len(store.runs()) == 1
    assert store.findings_by_provenance("real-world") == []


def test_real_world_findings_are_kept_apart_as_disclosure_candidates(store, tmp_path):
    store.ingest(recording(tmp_path, [finding(5)], name="a"))
    store.ingest(
        recording(
            tmp_path,
            [finding(5, server="someone-else")],
            name="b",
            provenance="real-world",
            entry="someone-else",
        )
    )
    assert [k["server"] for k in store.findings_by_provenance("real-world")] == ["someone-else"]
    assert [k["server"] for k in store.findings_by_provenance("poison")] == ["srv"]


def test_the_announced_name_is_kept_beside_the_run_and_not_in_any_key(store, tmp_path):
    path = recording(tmp_path, [finding(5)])
    store.ingest(path)
    info = store.run_info(store.resolve(str(path)))
    assert (info.server, info.announced_server) == ("srv", "srv-announced")
    assert all(k["server"] == "srv" for k in store.findings_by_provenance("poison"))


def test_the_store_file_is_readable_by_its_owner_only(tmp_path):
    with Store.open(tmp_path / "private.sqlite"):
        pass
    assert (tmp_path / "private.sqlite").stat().st_mode & 0o777 == 0o600


def test_a_store_of_another_schema_is_refused(tmp_path):
    path = tmp_path / "old.sqlite"
    with Store.open(path):
        pass
    connection = sqlite3.connect(path)
    connection.execute("UPDATE meta SET value = '1' WHERE name = 'schema'")
    connection.commit()
    connection.close()
    with pytest.raises(StoreError, match="schema 1"):
        Store.open(path)


def _store_of_schema(path: Path, schema: str) -> bytes:
    """A store as an older or other version left it: its own tables, a run in them, and its
    schema named in meta. Returns the file's bytes, to show that refusing it changed nothing."""
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "CREATE TABLE runs (run TEXT PRIMARY KEY, complete INTEGER NOT NULL);"
        "INSERT INTO runs VALUES ('" + "ab" * 32 + "', 1);"
    )
    connection.execute("INSERT INTO meta VALUES ('schema', ?)", (schema,))
    connection.commit()
    connection.close()
    return path.read_bytes()


@pytest.mark.parametrize("schema", ["2", "7", "8", "9", "10", "11"])
def test_a_store_of_an_earlier_schema_is_refused_whole_and_asks_for_the_runs_again(
    tmp_path, schema
):
    """Schema 2 is the store before the fleet, 7 the one before the kinds of shortfall, 9 the one
    before ``call_failed``, 10 the one before engagements and triage, 11 the one before the
    endpoint's certificates. None is migrated or read in part. The file is left as it was."""
    path = tmp_path / "old.sqlite"
    before = _store_of_schema(path, schema)
    with pytest.raises(StoreError) as refused:
        Store.open(path)
    message = str(refused.value)
    assert f"store schema {schema}, written by an earlier version of Kymograph" in message
    assert "reads no older store, not even in part" in message
    assert "Drive the corpus again into a new store" in message
    assert path.read_bytes() == before


@pytest.mark.parametrize("schema", ["14", "99", "seven"])
def test_a_store_of_an_unknown_schema_is_refused_whole(tmp_path, schema):
    path = tmp_path / "newer.sqlite"
    before = _store_of_schema(path, schema)
    with pytest.raises(StoreError) as refused:
        Store.open(path)
    message = str(refused.value)
    assert f"store schema {schema!r} is not one this version knows" in message
    assert "not read, not even in part" in message
    assert path.read_bytes() == before


def test_a_file_with_tables_but_no_schema_is_not_taken_for_a_new_store(tmp_path):
    """Before, a file without a schema row was stamped with the current schema and then read
    with whatever tables it had."""
    path = tmp_path / "other.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE runs (run TEXT)")
    connection.commit()
    connection.close()
    before = path.read_bytes()
    with pytest.raises(StoreError, match="names no store schema"):
        Store.open(path)
    assert path.read_bytes() == before


def test_an_empty_file_becomes_a_new_store(tmp_path):
    path = tmp_path / "empty.sqlite"
    path.touch(mode=0o600)
    with Store.open(path) as store:
        assert store.runs() == []


@pytest.mark.parametrize(
    ("schema", "fragment"),
    [
        (1, "the recording is schema 1, made by an earlier version of Kymograph; this version "
            f"reads schema {RECORDING_SCHEMA} only and no older recording, not even in part — "
            "drive the run again"),
        (RECORDING_SCHEMA + 1, f"the recording is schema {RECORDING_SCHEMA + 1}, which this "
                               "version does not know"),
        ("2", "the recording is schema '2', which this version does not know"),
        (None, "the recording is schema None, which this version does not know"),
    ],
)  # fmt: skip
def test_a_recording_of_another_schema_is_refused_whole_and_nothing_is_filed(
    store, tmp_path, schema, fragment
):
    path = recording(tmp_path, [finding(5)], schema=schema)
    with pytest.raises(StoreError) as refused:
        store.ingest(path)
    assert fragment in str(refused.value)
    assert store.runs() == []


def test_a_run_incomplete_for_udp_loss_says_so_in_the_store_past_the_listed_problems(
    store, tmp_path
):
    """Twenty-five unreadable lines come first and fill the listed problems; the loss is not
    among them. Its cause is kept whole beside them, and a run incomplete for another reason
    carries another one."""
    lossy = {
        "type": "egress_summary",
        "consistent": True,
        "udp_loss": {"kernel": 9, "sink": 8, "lost": 1, "unseen_destinations": 0},
    }
    loss = recording(
        tmp_path, [finding(5)], name="loss", isolation="runc", extra=[lossy, *["not json"] * 25]
    )
    gap = recording(tmp_path, [finding(5)], name="gap", script=False)
    filed = store.ingest(loss)
    other = store.ingest(gap)
    assert (filed.state, other.state) == (verdict.INCOMPLETE, verdict.INCOMPLETE)
    info = store.run_info(filed.run)
    assert len(info.problems) == 20 and not any("UDP" in p for p in info.problems)
    assert info.problem_count == 26
    assert info.causes == ("line", "udp_loss") == filed.causes
    assert store.run_info(other.run).causes == ("no_script_finished",)
    assert [run.to_dict()["causes"] for run in store.runs()] in (
        [["line", "udp_loss"], ["no_script_finished"]],
        [["no_script_finished"], ["line", "udp_loss"]],
    )


def test_a_finding_the_store_cannot_file_makes_the_run_incomplete_under_its_own_cause(
    store, tmp_path
):
    path = recording(tmp_path, [finding(5, server="someone-else")])
    filed = store.ingest(path)
    assert filed.state == verdict.INCOMPLETE
    assert filed.causes == ("unfiled_finding",)


def test_a_line_of_another_schema_in_a_recording_refuses_the_whole_recording(store, tmp_path):
    late = finding(5)
    late["v"] = 1
    path = recording(tmp_path, [finding(4), late])
    with pytest.raises(StoreError, match="lines of schema 1 in a recording of schema"):
        store.ingest(path)
    assert store.runs() == []


def test_a_recording_of_an_older_schema_is_judged_by_nothing_but_its_schema(tmp_path):
    """No partial verdict: the recording also lacks its script's end and its closing event,
    and neither is said — only that it is not of this version."""
    path = recording(tmp_path, [finding(5)], schema=1, script=False, finished=False)
    judged = verdict.read(path)
    assert judged.state == verdict.INCOMPLETE
    assert judged.problems == [
        "the recording is schema 1, made by an earlier version of Kymograph; this version "
        f"reads schema {RECORDING_SCHEMA} only and no older recording, not even in part — "
        "drive the run again"
    ]
    done = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "verdict", "-q", str(path)],
        capture_output=True, timeout=60, check=False,
    )  # fmt: skip
    assert done.returncode == verdict.EXIT_INCOMPLETE


# -- completeness: nothing missing passes for nothing found ---------------------------------


def test_a_complete_run_has_no_problems(store, tmp_path):
    filed = store.ingest(recording(tmp_path, [finding(5)]))
    assert filed.complete and filed.problems == ()


@pytest.mark.parametrize(
    ("variant", "fragment"),
    [
        ({"finished": False}, "no run_finished"),
        ({"counts": {"st": {"hidden_comment": 3}}}, "3 made, 1 recorded"),
        ({"counts": {}}, "recorded but not counted"),
        ({"extra": ["{not json"]}, "not JSON"),
        ({"extra": [{"seq": 7, "type": "finding", "key": {"signal": "x"}}]}, "exactly"),
        ({"extra": [finding(8, server_version="sha256:" + "bb" * 32)]}, "server_version differs"),
        ({"extra": [finding(8, tool_version="9.9.9")]}, "tool_version differs"),
        ({"extra": [finding(8, server="impostor")]}, "server differs"),
    ],
)
def test_a_run_with_a_gap_is_filed_as_incomplete_with_the_reason(
    store, tmp_path, variant, fragment
):
    """Every one of these is recorded against the run, not swallowed."""
    filed = store.ingest(recording(tmp_path, [finding(5)], **variant))
    assert filed.complete is False
    assert any(fragment in problem for problem in filed.problems), filed.problems


def test_a_run_whose_inspection_was_bounded_is_incomplete(store, tmp_path):
    path = recording(tmp_path, [finding(5)], finished=False)
    with path.open("a") as handle:
        counts = {"st": {"hidden_comment": 1}}
        handle.write(
            json.dumps(
                {
                    "v": RECORDING_SCHEMA,
                    "type": "run_finished",
                    "findings_by_statement": counts,
                    "inspection_bounded": 2,
                    "server_output_bytes": 100,
                    "client_input_bytes": 100,
                    "server_exited_first": False,
                }
            )
            + "\n"
        )
    filed = store.ingest(path)
    assert not filed.complete
    assert any("partly inspected" in problem for problem in filed.problems)


# -- comparing: the three sets --------------------------------------------------------------


def test_new_gone_and_unchanged_are_three_disjoint_sets(store, tmp_path):
    kept, lost, added = (finding(5, statement=s) for s in ("kept", "lost", "added"))
    asked = [(s, "hidden_comment") for s in ("kept", "lost", "added")]
    before = recording(tmp_path, [kept, lost], name="before", asked=asked)
    after = recording(tmp_path, [finding(5, statement="kept"), added], name="after", asked=asked)
    result = compare(store, before, after)
    assert [c.identity["statement"] for c in result.new] == ["added"]
    assert [c.identity["statement"] for c in result.gone] == ["lost"]
    assert [c.identity["statement"] for c in result.unchanged] == ["kept"]
    assert result.complete


def test_a_finding_whose_position_moved_is_unchanged(store, tmp_path):
    before = recording(tmp_path, [finding(5, "result.tools[0].description")], name="before")
    after = recording(tmp_path, [finding(5, "result.tools[1].description")], name="after")
    result = compare(store, before, after)
    assert (len(result.new), len(result.gone), len(result.unchanged)) == (0, 0, 1)
    (same,) = result.unchanged
    assert [s.path for s in same.seen_before] == ["result.tools[0].description"]
    assert [s.path for s in same.seen_after] == ["result.tools[1].description"]


def test_a_comparison_with_an_incomplete_run_says_it_is_incomplete(store, tmp_path):
    before = recording(tmp_path, [finding(5)], name="before")
    after = recording(tmp_path, [], name="after", finished=False)
    result = compare(store, before, after)
    assert [c.identity["statement"] for c in result.gone] == ["st"]
    assert result.complete is False, "gone from an incomplete run may only be missing"


def test_a_run_is_found_by_a_prefix_of_its_id_and_an_unknown_one_is_refused(store, tmp_path):
    filed = store.ingest(recording(tmp_path, [finding(5)]))
    assert store.resolve(filed.run[:8]) == filed.run
    with pytest.raises(StoreError, match="no such run"):
        store.resolve("ffffffff")
    with pytest.raises(StoreError, match="at least 8"):
        store.resolve("abc")


# -- comparing: which axis moved ------------------------------------------------------------

AXIS_CHANGES = {
    "server": {"version": "sha256:" + "cc" * 32},
    "server-launch": {"launch": "sha256:" + "44" * 32},
    "tool": {"tool": "9.9.9"},
    "tool-content": {"tool_content": "sha256:" + "55" * 32},
    "scenario": {"scenario_digest": "e" * 64},
}


def moved_run(tmp_path, change: dict, findings_of=lambda **k: [finding(5, **k)]):
    """The second run, with one change applied to its context — and to its keys, where the
    key carries that field, as a real run would."""
    key_fields = {}
    if "version" in change:
        key_fields["server_version"] = change["version"]
    if "tool" in change:
        key_fields["tool_version"] = change["tool"]
    return recording(tmp_path, findings_of(**key_fields), name="after", **change)


@pytest.mark.parametrize("axis", ["server", "server-launch", "tool", "tool-content", "scenario"])
def test_when_one_axis_moved_the_comparison_names_it(store, tmp_path, axis):
    before = recording(tmp_path, [finding(5)], name="before")
    after = moved_run(tmp_path, AXIS_CHANGES[axis])
    result = compare(store, before, after)
    expected = axis.split("-")[0]
    assert result.moved == (expected,)
    assert result.attribution.attributable and result.attribution.axis == expected
    assert len(result.unchanged) == 1, "matched without the versions"


def test_the_tool_axis_moves_with_its_content_even_when_its_version_does_not(store, tmp_path):
    """A version can stay the same across commits; the content digest does not.
    A tool change must not read as "nothing moved"."""
    before = recording(tmp_path, [finding(5)], name="before")
    after = recording(
        tmp_path,
        [finding(5, statement="new")],
        name="after",
        tool_content="sha256:" + "66" * 32,
        asked=[("st", "hidden_comment")],
    )
    result = compare(store, before, after)
    assert result.axes["tool"]["tool_version"] == {"before": __version__, "after": __version__}
    assert result.moved == ("tool",)
    assert result.attribution.axis == "tool"


def test_when_two_axes_moved_a_gone_finding_is_not_attributed(store, tmp_path):
    before = recording(tmp_path, [finding(5)], name="before")
    after = recording(
        tmp_path,
        [],
        name="after",
        version="sha256:" + "cc" * 32,
        tool_content="sha256:" + "66" * 32,
        asked=[("st", "hidden_comment")],
    )
    result = compare(store, before, after)
    assert len(result.gone) == 1
    assert set(result.moved) == {"server", "tool"}
    assert result.attribution.attributable is False and result.attribution.axis is None
    assert "cannot be put down" in result.attribution.note


def test_when_nothing_moved_but_findings_differ_the_comparison_says_nothing_explains_it(
    store, tmp_path
):
    before = recording(tmp_path, [finding(5)], name="before")
    after = recording(tmp_path, [], name="after", asked=[("st", "hidden_comment")])
    result = compare(store, before, after)
    assert result.moved == ()
    assert result.attribution.attributable is False
    assert "no recorded change explains" in result.attribution.note


def test_two_different_entries_are_not_a_change_of_one(store, tmp_path):
    before = recording(tmp_path, [finding(5)], name="before")
    after = recording(tmp_path, [finding(5, server="other")], name="after", entry="other")
    result = compare(store, before, after)
    assert result.to_dict()["same_entry"] is False
    assert result.attribution.attributable is False
    assert "different corpus entries" in result.attribution.note, "for that reason, not another"


# -- comparing: scenario drift --------------------------------------------------------------


def test_a_changed_scenario_flags_new_and_gone_softly_and_names_the_statements(store, tmp_path):
    """Complete data, another question: the sets carry a caveat, every entry whose statement
    exists on one side only says so, and the comparison is not incomplete."""
    before = recording(
        tmp_path,
        [finding(5, statement="removed"), finding(6, statement="both", signal="role_line")],
        name="before",
        asked=[("both", "hidden_comment"), ("both", "role_line"), ("removed", "hidden_comment")],
    )
    after = recording(
        tmp_path,
        [finding(5, statement="added"), finding(6, statement="both")],
        name="after",
        scenario_digest="e" * 64,
        asked=[("both", "hidden_comment"), ("both", "role_line"), ("added", "hidden_comment")],
    )
    result = compare(store, before, after)
    assert result.caveats == {"new": (SCENARIO_DRIFT,), "gone": (SCENARIO_DRIFT,)}
    assert {(c.identity["statement"], c.statement_hint) for c in result.new} == {
        ("added", "statement_added"),
        ("both", None),
    }
    assert {(c.identity["statement"], c.statement_hint) for c in result.gone} == {
        ("removed", "statement_removed"),
        ("both", None),
    }
    assert result.complete is True, "drift is not missing data"
    assert result.attribution.axis == "scenario"


def test_without_drift_there_is_no_caveat(store, tmp_path):
    before = recording(tmp_path, [finding(5)], name="before")
    after = recording(tmp_path, [finding(5)], name="after")
    assert compare(store, before, after).caveats == {"new": (), "gone": ()}


# -- end to end: real corpus runs of the poison server --------------------------------------


def manifest(tmp_path: Path, *extra: str) -> Path:
    """A one-entry manifest for the poison server, with extra launch arguments."""
    here = tmp_path / "corpus"
    here.mkdir(parents=True, exist_ok=True)

    def rel(path: Path) -> str:
        return os.path.relpath(path, here)

    command = ["{python}", str(POISON), *extra]
    (here / "manifest.json").write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "poison-server",
                        "provenance": "poison",
                        "source": {"paths": [rel(POISON), rel(DISCOVERY)]},
                        "launch": {"transport": "stdio", "command": command},
                        "scenarios": [rel(ALL_SIGNALS)],
                    }
                ],
            }
        )
    )
    return here / "manifest.json"


def drive_poison(out: Path, *extra: str) -> Path:
    done = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "drive",
            "-q",
            "--out-dir",
            str(out / "runs"),
            "--manifest",
            str(manifest(out, *extra)),
            "--entry",
            "poison-server",
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    (path,) = (out / "runs").glob("*/events.jsonl")
    return path


def store_cli(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mcp_kymograph.cli", "store", *arguments],
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_a_tool_put_in_front_is_unchanged_in_the_diff_end_to_end(tmp_path):
    """The case the locator was built for, through manifest, store and command line: the
    poison tool moves from [0] to [1] behind an inserted one, every key stays, the diff says
    unchanged — and names the server's launch as what moved."""
    before = drive_poison(tmp_path / "a")
    after = drive_poison(tmp_path / "b", "--leading-tool", "inserted")
    database = str(tmp_path / "findings.sqlite")
    filed = store_cli("ingest", "--store", database, str(before), str(after))
    assert filed.returncode == 0, filed.stderr

    compared = store_cli("diff", "--store", database, str(before), str(after))
    assert compared.returncode == 0, compared.stderr
    result = json.loads(compared.stdout)
    assert (len(result["new"]), len(result["gone"]), len(result["unchanged"])) == (0, 0, 4)
    for entry in result["unchanged"]:
        assert entry["key_before"] == entry["key_after"]
        assert [s["path"] for s in entry["sightings_before"]] == ["result.tools[0].description"]
        assert [s["path"] for s in entry["sightings_after"]] == ["result.tools[1].description"]
    assert result["moved_axes"] == ["server"]
    assert (
        result["axes"]["server"]["server_version"]["before"]
        == (result["axes"]["server"]["server_version"]["after"])
    ), "the same files: only how they were launched moved"


def test_a_renamed_tool_is_gone_and_new_end_to_end(tmp_path):
    """A rename is a change: the old name's findings go, the new name's arrive."""
    before = drive_poison(tmp_path / "a")
    after = drive_poison(tmp_path / "b", "--tool-name", "renamed")
    database = str(tmp_path / "findings.sqlite")
    assert store_cli("ingest", "--store", database, str(before), str(after)).returncode == 0
    result = json.loads(store_cli("diff", "--store", database, str(before), str(after)).stdout)
    assert len(result["unchanged"]) == 0
    assert {e["identity"]["locator"] for e in result["gone"]} == {
        'result.tools[name="tool_0"].description'
    }
    assert {e["identity"]["locator"] for e in result["new"]} == {
        'result.tools[name="renamed"].description'
    }
    assert len(result["gone"]) == len(result["new"]) == 4
    assert result["attribution"]["axis"] == "server"


def test_the_command_line_says_when_a_comparison_involves_an_incomplete_run(tmp_path):
    database = str(tmp_path / "findings.sqlite")
    complete = drive_poison(tmp_path / "a")
    broken = tmp_path / "broken.jsonl"
    broken.write_text("\n".join(complete.read_text().splitlines()[:-1]) + "\n")  # no closing event
    filed = store_cli("ingest", "--store", database, str(complete), str(broken))
    assert filed.returncode == cli.EXIT_INCOMPLETE
    assert b"INCOMPLETE" in filed.stderr
    compared = store_cli("diff", "--store", database, str(complete), str(broken))
    assert compared.returncode == cli.EXIT_INCOMPLETE
    assert json.loads(compared.stdout)["complete"] is False


def test_a_plain_run_without_a_manifest_is_refused_by_the_store(tmp_path):
    done = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "mcp_kymograph.cli",
            "drive",
            "-q",
            "--out-dir",
            str(tmp_path / "runs"),
            "--scenario",
            str(ALL_SIGNALS),
            "--server-content",
            str(POISON),
            "--",
            sys.executable,
            str(POISON),
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    (path,) = (tmp_path / "runs").glob("*/events.jsonl")
    filed = store_cli("ingest", "--store", str(tmp_path / "f.sqlite"), str(path))
    assert filed.returncode == cli.EXIT_REFUSED
    assert b"--manifest" in filed.stderr


# -- values from the traffic never end the filing with an unnamed exception ----------------


def rewritten(path, change):
    """The recording at ``path`` with ``change(events)`` applied to its parsed lines."""
    events = [json.loads(line) for line in path.read_text().splitlines()]
    change(events)
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return path


def with_message_seq(tmp_path, value, *, name="run", seq=5):
    path = recording(tmp_path, [finding(seq)], name=name)
    return rewritten(path, lambda events: events[1].update(message_seq=value))


def count(store, table):
    return store._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


def test_an_announced_name_with_a_lone_surrogate_is_filed_without_it(store, tmp_path):
    """Chosen: filed, the surrogate replaced by U+FFFD (as the inspector now does, and as the
    verdict does when it reads a recording that still holds one). The name is only kept beside
    the run, never in a key, so a refusal would lose a whole run for a cosmetic character."""
    path = recording(tmp_path, [finding(5)])
    rewritten(path, lambda events: events[-1].update(announced_server="srv\ud800"))
    assert "\\ud800" in path.read_text()
    store.ingest(path)
    announced = store.run_info(store.resolve(str(path))).announced_server
    assert announced == "srv\N{REPLACEMENT CHARACTER}"


def test_a_message_seq_beyond_64_bits_is_refused_with_a_reason(store, tmp_path):
    with pytest.raises(StoreError, match=r"message_seq.*64-bit"):
        store.ingest(with_message_seq(tmp_path, 10**40))
    assert count(store, "runs") == 0


@pytest.mark.parametrize(
    ("field", "value"), [("server_identity", 5), ("authorization", "x"), ("authorization", [])]
)
def test_a_context_that_is_no_object_is_refused_not_a_crash(store, tmp_path, field, value):
    path = rewritten(
        recording(tmp_path, [finding(5)]), lambda events: events[0].update({field: value})
    )
    with pytest.raises(StoreError, match=f"{field} is not an object"):
        store.ingest(path)
    assert count(store, "runs") == 0


def test_a_series_goes_on_past_a_run_that_is_refused(store, tmp_path):
    first = recording(tmp_path, [finding(5)], name="first")
    middle = with_message_seq(tmp_path, 10**40, name="middle", seq=6)
    last = recording(tmp_path, [finding(7)], name="last")
    done = dict(ingest_all(store, [first, middle, last]))
    assert isinstance(done[first], Ingested)
    assert isinstance(done[last], Ingested)
    assert isinstance(done[middle], StoreError)
    assert count(store, "runs") == 2


def test_a_value_the_database_cannot_hold_refuses_the_run_and_rolls_it_back(store, tmp_path):
    """A lone surrogate where nothing cleans it (the run's id) fails at the first INSERT: the
    refusal is a StoreError, and nothing of the run stays."""
    path = recording(tmp_path, [finding(5)])
    rewritten(path, lambda events: events[0].update(run_id="id\ud800"))
    with pytest.raises(StoreError, match="cannot be stored"):
        store.ingest(path)
    assert (count(store, "runs"), count(store, "findings"), count(store, "sightings")) == (0, 0, 0)


def test_a_value_that_fails_after_the_run_is_written_rolls_the_whole_run_back(store, tmp_path):
    """A surrogate in a sighting's path fails at an INSERT after the run's own row is written:
    the refusal rolls back the run's row and its findings too, and the runs before it stay."""
    store.ingest(recording(tmp_path, [finding(5)], name="kept"))
    with pytest.raises(StoreError, match="cannot be stored"):
        store.ingest(
            recording(tmp_path, [finding(6, path="result.tools[0].descr\ud800")], name="late")
        )
    assert (count(store, "runs"), count(store, "findings"), count(store, "sightings")) == (1, 1, 1)


def test_a_refusal_leaves_nothing_of_the_run_but_keeps_the_runs_before_it(store, tmp_path):
    store.ingest(recording(tmp_path, [finding(5)], name="kept"))
    with pytest.raises(StoreError):
        store.ingest(with_message_seq(tmp_path, -(2**63) - 1, name="refused", seq=6))
    assert (count(store, "runs"), count(store, "findings"), count(store, "sightings")) == (1, 1, 1)


def test_a_server_that_names_itself_with_a_lone_surrogate_is_driven_and_filed(tmp_path):
    here = tmp_path / "corpus"
    here.mkdir()
    server = FIXTURES / "corpus" / "surrogate_server.py"

    def rel(path: Path) -> str:
        return os.path.relpath(path, here)

    entry = {
        "name": "surrogate-server",
        "provenance": "poison",
        "source": {"paths": [rel(server), rel(DISCOVERY)]},
        "launch": {"transport": "stdio", "command": ["{python}", str(server)]},
        "scenarios": [rel(ALL_SIGNALS)],
    }
    (here / "manifest.json").write_text(json.dumps({"version": 1, "entries": [entry]}))
    done = subprocess.run(  # noqa: S603
        [
            *(sys.executable, "-m", "mcp_kymograph.cli", "drive", "-q"),
            *("--out-dir", str(tmp_path / "runs")),
            *("--manifest", str(here / "manifest.json")),
            *("--entry", "surrogate-server"),
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    (path,) = (tmp_path / "runs").glob("*/events.jsonl")
    events = [json.loads(line) for line in path.read_text().splitlines()]
    (answer,) = (
        e for e in events if e["type"] == "message" and e["responded_method"] == "initialize"
    )
    (seen,) = (e for e in events if e["type"] == "observation")
    assert (seen["surface"], seen["signal"], seen["path"]) == (
        "server_info",
        "lone_surrogate",
        "result.serverInfo.name",
    )
    assert seen["message_seq"] == answer["seq"]
    (finished,) = (e for e in events if e["type"] == "run_finished")
    assert finished["observations_by_method"]["initialize"] == 1
    filed = store_cli("ingest", "--store", str(tmp_path / "findings.sqlite"), str(path))
    assert filed.returncode == 0, filed.stderr
    assert b"Traceback" not in filed.stderr


def test_each_run_keeps_its_recording_as_it_was_given_at_ingest(tmp_path, monkeypatch):
    first = recording(tmp_path, [], name="one", entry="one")
    second = recording(tmp_path, [], name="two", entry="two")
    monkeypatch.chdir(tmp_path)
    with Store.open(tmp_path / "findings.sqlite") as store:
        filed = {store.ingest(first.name).run: first.name, store.ingest(second).run: str(second)}

        assert store.recordings() == filed
