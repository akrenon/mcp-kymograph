"""A comparison across two stores is the comparison within one that holds both runs.

``store.compare_runs`` reads each side whole from its own store — the run as filed there and the
findings it sighted — so a run of this engagement's store compares with one in an earlier
bundle's copy exactly as ``Store.diff`` compares two runs of one store. Tested for runs that
differ on every axis, in their rules, the kind of their version and their caps; and a run a
store does not hold is refused there, in the words ``Store.diff`` uses.
"""

import hashlib
import json
import sqlite3
from contextlib import closing

import pytest

from mcp_kymograph.store import Store, StoreError, compare_runs
from test_store import VERSION, finding, recording

LATER = "sha256:" + "bb" * 32
CAPPED = {
    "seq": 50,
    "type": "findings_capped",
    "message_seq": 4,
    "method": "tools/list",
    "cap": 1,
    "made": 2,
    "recorded": 1,
    "cut": {"gone": {"hidden_comment": 1}},
}


def edited(path, change):
    """The recording with its run_started changed by ``change``."""
    lines = path.read_text().splitlines()
    started = json.loads(lines[0])
    change(started)
    lines[0] = json.dumps(started)
    path.write_text("\n".join(lines) + "\n")
    return path


def as_endpoint(started):
    for identity in (started["server_identity"], started["reproduction"]["corpus"]["identity"]):
        identity["kind"] = "endpoint"


EARLIER = [finding(5, statement="kept"), finding(6, statement="gone")]

#: Per case: what the later run changes against the earlier one.
CASES = {
    "server": {"version": LATER, "server_version": LATER},
    "launch": {"launch": "sha256:" + "23" * 32},
    "tool": {"tool_content": "sha256:" + "12" * 32},
    "scenario": {"scenario_digest": "e" * 64},
    "environment": {"isolation": "runc", "egress": True},
    "images": {"isolation": "runc", "egress": True, "sandbox_image": "sha256:" + "5c" * 32},
    "caps": {"capped": True},
    "declared": {"endpoint": True},
    "nothing": {},
}


def made(tmp_path, name, changes):
    server_version = changes.get("server_version", VERSION)
    findings = [
        finding(5, statement="kept", server_version=server_version),
        finding(7, statement="new", server_version=server_version),
    ]
    extra = []
    if changes.get("egress"):
        extra.append({"seq": 97, "type": "egress_summary", "consistent": True,
                      "udp_loss": {"kernel": 0, "sink": 0, "lost": 0}})  # fmt: skip
    if changes.get("capped"):
        extra.append(CAPPED)
    options = {
        key: value
        for key, value in changes.items()
        if key in ("version", "launch", "tool_content", "scenario_digest", "isolation",
                   "sandbox_image")
    }  # fmt: skip
    path = recording(tmp_path, findings, name=name, extra=extra, **options)
    return edited(path, as_endpoint) if changes.get("endpoint") else path


def stores(tmp_path, before, after, *, rules=None):
    """Three stores: one with each run, one with both. ``rules`` sets the later run's rules."""
    paths = {name: tmp_path / f"{name}.sqlite" for name in ("first", "second", "both")}
    for name, recordings in (("first", [before]), ("second", [after]), ("both", [before, after])):
        with Store.open(paths[name]) as store:
            for path in recordings:
                store.ingest(path)
    if rules is not None:
        for name in ("second", "both"):
            with closing(sqlite3.connect(paths[name])) as connection, connection:
                connection.execute(
                    "UPDATE runs SET rules = ? WHERE recording = ?", (rules, str(after))
                )
    return paths


def run_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("case", sorted(CASES))
def test_across_two_stores_is_the_same_as_within_one(tmp_path, case):
    before = recording(tmp_path, EARLIER, name="before")
    after = made(tmp_path, "after", CASES[case])
    paths = stores(tmp_path, before, after)
    earlier, later = run_of(before), run_of(after)

    with Store.open(paths["both"]) as both:
        expected = both.diff(earlier, later).to_dict()
    with Store.open_read_only(paths["first"]) as first, Store.open(paths["second"]) as second:
        across = compare_runs(first, earlier, second, later).to_dict()
    assert across == expected
    if case != "nothing":
        assert (
            expected["moved_axes"]
            or expected["caveats"]["gone"]
            or (expected["server_version_kind"]["after"] == "declared")
        )


def test_each_side_is_read_from_its_own_store(tmp_path):
    """Rules, the version's kind, the environment and the caps of each side come from the
    store that holds it: here the later run differs in all of them at once."""
    before = recording(tmp_path, EARLIER, name="before")
    after = made(tmp_path, "after", {"isolation": "runc", "egress": True, "capped": True,
                                     "endpoint": True})  # fmt: skip
    paths = stores(tmp_path, before, after, rules=1)
    earlier, later = run_of(before), run_of(after)
    with Store.open(paths["both"]) as both:
        expected = both.diff(earlier, later).to_dict()
    with (
        Store.open_read_only(paths["first"]) as first,
        Store.open_read_only(paths["second"]) as second,
    ):
        across = compare_runs(first, earlier, second, later).to_dict()
    assert across == expected
    assert across["rules"]["after"] == 1 and across["rules"]["moved"]
    assert across["server_version_kind"] == {"before": "content", "after": "declared"}
    assert across["axes"]["environment"]["isolation"] == {"before": "host", "after": "runc"}
    assert across["after"]["truncations"] and not across["before"]["truncations"]
    assert [c["cap_hint"] for c in across["gone"]] == ["capped_after"]


def test_the_same_store_twice_is_store_diff(tmp_path):
    before = recording(tmp_path, EARLIER, name="before")
    after = made(tmp_path, "after", CASES["server"])
    paths = stores(tmp_path, before, after)
    with Store.open(paths["both"]) as both:
        assert (
            compare_runs(both, run_of(before), both, run_of(after)).to_dict()
            == both.diff(run_of(before), run_of(after)).to_dict()
        )


def test_a_run_a_store_does_not_hold_is_refused_there(tmp_path):
    before = recording(tmp_path, EARLIER, name="before")
    after = made(tmp_path, "after", CASES["server"])
    paths = stores(tmp_path, before, after)
    earlier, later = run_of(before), run_of(after)
    with (
        Store.open_read_only(paths["first"]) as first,
        Store.open_read_only(paths["second"]) as second,
    ):
        # Each run is looked for in its own store only, never in the other.
        with pytest.raises(StoreError) as refused:
            compare_runs(first, later, second, earlier)
        assert str(refused.value) == f"{later}: no such run in the store"
        with pytest.raises(StoreError) as refused:
            compare_runs(first, earlier, second, earlier)
        assert str(refused.value) == f"{earlier}: no such run in the store"
        missing = "0" * 64
        with pytest.raises(StoreError, match=f"{missing}: no such run in the store"):
            compare_runs(first, missing, second, later)
