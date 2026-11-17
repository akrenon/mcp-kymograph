"""A server's timeline: every identity of its findings, fleet by fleet and run by run.

Each cell says what the store holds and nothing more: ``sighted`` where the run sighted the
finding, ``not_sighted`` where a complete run that could have reported it did not,
``not_a_result`` — with the run's state — where the run was no result to go by, ``not_asked``,
``capped`` and ``listing_capped`` where a complete run could not have reported it, and
``not_run`` where that column ran nothing of the identity's scenario. A run that was not a
result, or could not have said, is never read as one that saw nothing.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from mcp_kymograph.store import Store, StoreError
from test_store import VERSION, finding, recording
from test_store_engagement import fleet_row
from test_store_triage import IDENTITY

LATER = "sha256:" + "bb" * 32
START = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


#: What every run's scenario asks unless a test says otherwise: both statements of the fixture.
ASKED = (("st", "hidden_comment"), ("other", "hidden_comment"))


def at(tmp_path, name, findings, hours, **options):
    """A recording of ``srv`` made ``hours`` after START: another time, so other bytes. Its
    scenario asks :data:`ASKED` unless ``asked`` says otherwise."""
    options.setdefault("asked", ASKED)
    path = recording(tmp_path, findings, name=name, **options)
    lines = path.read_text().splitlines()
    started = json.loads(lines[0])
    started["wall_clock_utc"] = (START + timedelta(hours=hours)).isoformat(timespec="milliseconds")
    lines[0] = json.dumps(started)
    path.write_text("\n".join(lines) + "\n")
    return path


def result(run, state="complete", scenario="scn"):
    return {"entry": "srv", "scenario": scenario, "provenance": "poison", "state": state,
            "exit_code": 0, "run": run, "problems": []}  # fmt: skip


@pytest.fixture
def timeline(tmp_path):
    with Store.open(tmp_path / "s.sqlite") as store:
        first = store.ingest(at(tmp_path, "r1", [finding(5), finding(6, statement="other")], 1))
        second = store.ingest(at(tmp_path, "r2", [finding(6, statement="other")], 2))
        third = store.ingest(at(tmp_path, "r3", [], 3, finished=False))
        outside = store.ingest(
            at(tmp_path, "r4", [finding(5, server_version=LATER)], 4, version=LATER)
        )
        store.file_fleet(fleet_row("f1"), [result(first.run)])
        store.file_fleet(fleet_row("f2"), [result(second.run)])
        store.file_fleet(fleet_row("f3"), [result(third.run, "incomplete"),
                                           {**result(None, "refused"), "entry": "srv",
                                            "scenario": "other-scenario"}])  # fmt: skip
        store.triage_set(identity=IDENTITY, role="operator", status="confirmed",
                         author="A. Operator")  # fmt: skip
        yield store, [first.run, second.run, third.run, outside.run]


def cells(row):
    return [(cell["cell"], cell["state"]) for cell in row["cells"]]


def test_each_identity_has_a_cell_per_fleet_and_per_run_outside_a_fleet(timeline):
    store, (first, second, third, outside) = timeline
    assert third and store.run_info(third).state == "incomplete"

    history = store.history("srv")

    assert history["server"] == "srv"
    assert [(c["kind"], c.get("fleet"), c.get("run")) for c in history["columns"]] == [
        ("fleet", "f1", None),
        ("fleet", "f2", None),
        ("fleet", "f3", None),
        ("run", None, outside),
    ]
    by_statement = {row["identity"]["statement"]: row for row in history["identities"]}
    assert set(by_statement) == {"st", "other"}
    st = by_statement["st"]
    assert st["identity"] == IDENTITY
    assert cells(st) == [
        ("sighted", "complete"),
        ("not_sighted", "complete"),
        ("not_a_result", "incomplete"),
        ("sighted", "complete"),
    ]
    assert [cell["run"] for cell in st["cells"]] == [first, second, third, outside]
    assert st["first_utc"] == "2026-10-01T13:00:00.000+00:00"
    assert st["last_utc"] == "2026-10-01T16:00:00.000+00:00"
    assert st["server_versions"] == [
        {"server_version": VERSION, "server_version_kind": "content"},
        {"server_version": LATER, "server_version_kind": "content"},
    ]
    assert st["triage"]["operator"]["status"] == "confirmed"
    assert st["triage"]["customer"] is None

    other = by_statement["other"]
    assert cells(other) == [
        ("sighted", "complete"),
        ("sighted", "complete"),
        ("not_a_result", "incomplete"),
        ("not_sighted", "complete"),
    ]
    assert other["triage"] == {"operator": None, "customer": None}


def test_an_incomplete_run_is_never_not_sighted(timeline):
    store, (_, _, third, _) = timeline
    for row in store.history("srv")["identities"]:
        (cell,) = [cell for cell in row["cells"] if cell["run"] == third]
        assert cell["cell"] == "not_a_result"
        assert cell["state"] == "incomplete"


def test_a_column_that_ran_nothing_of_the_scenario_says_so(tmp_path):
    with Store.open(tmp_path / "s.sqlite") as store:
        run = store.ingest(at(tmp_path, "r1", [finding(5)], 1)).run
        store.file_fleet(fleet_row("f1"), [result(run)])
        store.file_fleet(fleet_row("f2"), [result(None, "refused")])
        store.file_fleet(fleet_row("f3"), [result(None, "refused", scenario="another")])
        (row,) = store.history("srv")["identities"]
    assert cells(row) == [
        ("sighted", "complete"),
        ("not_a_result", "refused"),
        ("not_run", None),
    ]


def test_a_server_the_store_has_not_run_is_refused(timeline):
    store, _ = timeline
    with pytest.raises(StoreError, match="'nobody': no run of this server in the store"):
        store.history("nobody")


def test_a_fleet_of_other_servers_is_not_a_column(tmp_path):
    with Store.open(tmp_path / "s.sqlite") as store:
        run = store.ingest(at(tmp_path, "r1", [finding(5)], 1)).run
        other = store.ingest(at(tmp_path, "r2", [], 2, entry="else")).run
        store.file_fleet(fleet_row("f1"), [result(run)])
        store.file_fleet(fleet_row("f2"), [{**result(other), "entry": "else"}])
        history = store.history("srv")
    assert [c.get("fleet") for c in history["columns"]] == ["f1"]


# -- a complete run that could not have reported the finding --------------------------------

#: The per-message cap cut the one finding of st/hidden_comment in that message: the run made
#: it, counted it, and recorded only the other one.
CUT = {"seq": 50, "type": "findings_capped", "message_seq": 4, "method": "tools/list", "cap": 1,
       "made": 2, "recorded": 1, "cut": {"st": {"hidden_comment": 1}}}  # fmt: skip
COUNTED = {"st": {"hidden_comment": 1}, "other": {"hidden_comment": 1}}
#: A listing cut at the driver's page limit.
PAGED = {"seq": 51, "type": "step_skipped", "step": "tools/list", "reason": "page_limit_reached",
         "detail": "20"}  # fmt: skip


@pytest.mark.parametrize(
    ("options", "cell"),
    [
        ({"asked": (("other", "hidden_comment"),)}, "not_asked"),
        ({"asked": (("st", "other_signal"), ("other", "hidden_comment"))}, "not_asked"),
        ({"extra": [CUT], "counts": COUNTED}, "capped"),
        ({"extra": [PAGED]}, "listing_capped"),
        ({"extra": [CUT, PAGED], "counts": COUNTED}, "capped"),
        ({}, "not_sighted"),
    ],
    ids=["statement", "signal", "cap", "listing", "cap-and-listing", "could-have"],
)
def test_a_complete_run_that_could_not_have_reported_it_is_not_not_sighted(tmp_path, options, cell):
    """On a timeline, not_sighted after sighted reads as "fixed": it is said only where the run
    asked, cut nothing of it and listed in full."""
    with Store.open(tmp_path / "s.sqlite") as store:
        first = store.ingest(at(tmp_path, "r1", [finding(5), finding(6, statement="other")], 1))
        later = store.ingest(at(tmp_path, "r2", [finding(6, statement="other")], 2, **options))
        assert later.state == "complete", later.problems
        rows = {row["identity"]["statement"]: row for row in store.history("srv")["identities"]}
    assert [c["run"] for c in rows["st"]["cells"]] == [first.run, later.run]
    assert cells(rows["st"]) == [("sighted", "complete"), (cell, "complete")]
    # The other identity was sighted by both runs, whatever they cut or did not ask of st.
    assert cells(rows["other"]) == [("sighted", "complete"), ("sighted", "complete")]


def test_a_run_that_was_no_result_stays_not_a_result_whatever_it_asked(tmp_path):
    with Store.open(tmp_path / "s.sqlite") as store:
        store.ingest(at(tmp_path, "r1", [finding(5)], 1))
        later = store.ingest(
            at(tmp_path, "r2", [], 2, asked=(("other", "hidden_comment"),), finished=False)
        )
        assert later.state == "incomplete"
        (row,) = store.history("srv")["identities"]
    assert cells(row) == [("sighted", "complete"), ("not_a_result", "incomplete")]
