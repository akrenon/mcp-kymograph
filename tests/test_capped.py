"""The per-message cap on findings is a recorded state, not a gap.

One message may record 20 findings. Past that, the run used to count more than it recorded
and was filed incomplete — exit 3 for every server with a long, loud tool list. Now a message
that reaches the cap says what it cut, per statement and signal, with the true numbers: the
run is complete, its truncation kept beside it, and a comparison says where the cut reaches.

The other direction is held too: a cut that is claimed and does not add up, or a cap whose
own record was lost, leaves the count short — and that is missing data again.
"""

import json
import os
from pathlib import Path

import pytest

from mcp_kymograph import cli, verdict
from mcp_kymograph.inspection import MAX_FINDINGS_PER_MESSAGE
from mcp_kymograph.store import FINDINGS_CAPPED, LISTING_CAPPED, Store

FIXTURES = Path(__file__).parent / "fixtures"
SERVER = FIXTURES / "discovery_server.py"
POISON = FIXTURES / "corpus" / "poison_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"

#: The four signals the poison description fires, in the scenario's statement order.
FIRED = [
    ("descriptions-instruction_override", "instruction_override"),
    ("descriptions-concealment_directive", "concealment_directive"),
    ("descriptions-hidden_comment", "hidden_comment"),
    ("descriptions-imperative", "imperative"),
]


def manifest(tmp_path: Path, *launch_args: str) -> Path:
    def rel(path: Path) -> str:
        return os.path.relpath(path, tmp_path)

    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "poison-server",
                        "provenance": "poison",
                        "source": {"paths": [rel(POISON), rel(SERVER)]},
                        "launch": {
                            "transport": "stdio",
                            "command": ["{python}", str(POISON), *launch_args],
                        },
                        "scenarios": [rel(ALL_SIGNALS)],
                    }
                ],
            }
        )
    )
    return path


def drive(tmp_path: Path, *launch_args: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = tmp_path / "runs"
    code = cli.main(
        ["drive", "-q", "--out-dir", str(out), "--manifest", str(manifest(tmp_path, *launch_args)),
         "--entry", "poison-server"]
    )  # fmt: skip
    (path,) = out.glob("*/events.jsonl")
    return code, path, [json.loads(line) for line in path.read_text().splitlines()]


def test_a_message_past_the_cap_is_complete_and_says_what_it_cut(tmp_path):
    """Six poisoned tools, four signals each: 24 findings in one message. The first 20 are
    recorded, in statement order; the last statement's last four are cut, and the recording
    says so with the true numbers. Exit 0, filed complete, the truncation kept."""
    code, path, events = drive(tmp_path, "--tool-count", "6")
    assert code == 0
    findings = [e for e in events if e["type"] == "finding"]
    assert len(findings) == MAX_FINDINGS_PER_MESSAGE
    (capped,) = [e for e in events if e["type"] == "findings_capped"]
    assert (capped["made"], capped["recorded"]) == (24, MAX_FINDINGS_PER_MESSAGE)
    assert capped["cap"] == MAX_FINDINGS_PER_MESSAGE
    assert capped["cut"] == {"descriptions-imperative": {"imperative": 4}}
    assert capped["message_seq"] == findings[0]["message_seq"]
    counted = events[-1]["findings_by_statement"]
    assert all(counted[statement][signal] == 6 for statement, signal in FIRED)

    judged = verdict.read(path)
    assert judged.state == verdict.COMPLETE, judged.problems
    (truncation,) = judged.truncations
    assert truncation["kind"] == "findings_per_message" and truncation["made"] == 24

    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.ingest(path)
        assert filed.state == verdict.COMPLETE and filed.findings == 20
        (run,) = store.runs()
        assert run.cut_statements == {("descriptions-imperative", "imperative")}
        assert run.to_dict()["truncations"][0]["cut"] == capped["cut"]


def test_below_the_cap_nothing_is_cut_and_nothing_says_so(tmp_path):
    code, path, events = drive(tmp_path, "--tool-count", "5")
    assert code == 0
    assert len([e for e in events if e["type"] == "finding"]) == 20
    assert not [e for e in events if e["type"] == "findings_capped"]
    assert verdict.read(path).truncations == []


# -- the other direction: a cut that does not add up is missing data -------------------------


def started():
    return {"type": "run_started", "mode": "driver", "isolation": "host"}


def finding(n, statement="st", signal="imperative"):
    return {
        "type": "finding",
        "seq": 10 + n,
        "key": {"statement": statement, "signal": signal},
        "path": f"result.tools[{n}].description",
        "message_seq": 4,
    }


def run(recorded, made, cut):
    events = [started(), *(finding(n) for n in range(recorded))]
    if cut is not None:
        events.append({"type": "findings_capped", "message_seq": 4, "cap": 20, "cut": cut})
    events.append({"type": "script_finished", "inventory": "complete"})
    events.append({"type": "run_finished", "findings_by_statement": {"st": {"imperative": made}},
                   "server_output_bytes": 100, "client_input_bytes": 100,
                   "server_exited_first": False})  # fmt: skip
    return verdict.assess(events)


def test_recorded_plus_cut_must_be_exactly_what_was_made():
    assert run(20, 24, {"st": {"imperative": 4}}).state == verdict.COMPLETE


@pytest.mark.parametrize(
    ("recorded", "made", "cut", "fragment"),
    [
        (20, 24, None, "24 made, 20 recorded"),  # the cap's own record was lost
        (20, 24, {"st": {"imperative": 3}}, "24 made, 20 recorded, 3 cut"),  # claims too little
        (20, 24, {"st": {"imperative": 5}}, "24 made, 20 recorded, 5 cut"),  # claims too much
        (19, 24, {"st": {"imperative": 4}}, "24 made, 19 recorded, 4 cut"),  # a finding dropped
        (20, 20, {"other": {"imperative": 1}}, "recorded but not counted"),
    ],
)
def test_a_cut_that_does_not_add_up_is_missing_data(recorded, made, cut, fragment):
    judged = run(recorded, made, cut)
    assert judged.state == verdict.INCOMPLETE
    assert any(fragment in p for p in judged.problems), judged.problems


# -- comparing across a cap ------------------------------------------------------------------


def test_a_finding_gone_where_the_later_run_cut_says_it_may_only_be_cut(tmp_path):
    """Five tools, nothing cut; then six, and the imperative cut to two. Three imperative
    findings are gone — and each says the later run cut that statement and signal, the set
    is flagged, softly, and the comparison stays complete (exit 0)."""
    before_code, before, _ = drive(tmp_path / "before", "--tool-count", "5")
    after_code, after, _ = drive(tmp_path / "after", "--tool-count", "6")
    assert before_code == after_code == 0
    database = str(tmp_path / "store.sqlite")
    assert cli.main(["store", "ingest", "-q", "--store", database, str(before), str(after)]) == 0
    with Store.open(database) as store:
        result = store.diff(store.resolve(str(before)), store.resolve(str(after)))
    assert result.complete
    assert {(c.identity["signal"], c.cap_hint) for c in result.gone} == {
        ("imperative", "capped_after")
    }
    assert len(result.gone) == 3
    assert {c.cap_hint for c in result.new} == {None}  # the earlier run cut nothing
    assert len(result.new) == 3  # three signals on the sixth tool, recorded
    assert FINDINGS_CAPPED in result.caveats["gone"]
    assert FINDINGS_CAPPED not in result.caveats["new"]
    code = cli.main(["store", "diff", "-q", "--store", database, str(before), str(after)])
    assert code == 0


def test_a_listing_cut_at_the_page_limit_flags_the_comparison(tmp_path):
    """Either run cut a listing at the page limit: what lay past it was not looked at there,
    so new and gone are flagged, softly. A set with nothing in it has nothing to flag."""
    from test_store import finding as filed_finding
    from test_store import recording

    capped = {"seq": 50, "type": "step_skipped", "step": "tools/list",
              "reason": "page_limit_reached", "detail": "20"}  # fmt: skip
    before = recording(tmp_path, [filed_finding(5, statement="a")], name="before", extra=[capped])
    after = recording(tmp_path, [filed_finding(5, statement="b")], name="after")
    with Store.open(tmp_path / "store.sqlite") as store:
        store.ingest(before)
        store.ingest(after)
        first, second = store.resolve(str(before)), store.resolve(str(after))
        assert store.run_info(first).listing_capped and store.run_info(first).complete
        result = store.diff(first, second)
        same = store.diff(second, second)
    assert result.complete
    assert LISTING_CAPPED in result.caveats["new"] and LISTING_CAPPED in result.caveats["gone"]
    assert same.caveats == {"new": (), "gone": ()}
