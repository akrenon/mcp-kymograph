"""A fleet under an engagement file: held to it before anything starts, and handing it on.

With the stand-in launcher of tests/test_fleet.py, filing made-up recordings into the real store,
so nothing here needs Docker. A refusal is whole: no launch, no directory, no fleet.json, no row.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mcp_kymograph import engagement, fleet
from mcp_kymograph.fleet import FleetError
from mcp_kymograph.store import Store
from test_fleet import ALL_SIGNALS, PINS, REFERENCE, _never, made_up, pair, write_manifest

NOW = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)
SCENARIO_SHA = hashlib.sha256(ALL_SIGNALS.read_bytes()).hexdigest()


def engagement_file(directory: Path, name: str = "engagement.json", **changes) -> Path:
    """A file covering the fixture corpus as a fleet runs it: the local child under runc."""
    data = {
        "version": 1,
        "id": "acme-2026-10",
        "customer": "ACME Corp",
        "reference": "SOW-17",
        "contacts": [{"name": "Dana", "reach": "+49 30 1234"}],
        "window": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
        "targets": [{"host": "localhost", "isolation": "runc"}],
        "scenarios": [{"path": os.path.relpath(ALL_SIGNALS, directory), "sha256": SCENARIO_SHA}],
        "actions": {"list": True, "call": False},
        "retention": {"delete_after": "2027-01-31"},
        "redaction": {"mask_keys": ["customer_id"]},
    }
    data.update(changes)
    path = directory / name
    path.write_text(json.dumps(data))
    return path


def launcher_under(digest: str):
    """The stand-in launcher; each recording names ``digest`` as its engagement's, as a child
    run under ``--engagement`` records it. Remembers what it was handed."""
    handed = []

    def launch(job, pins, manifest_path, out_dir, *, step_timeout, job_timeout,
               client_settle_timeout, processes, engagement_path=None):  # fmt: skip
        handed.append((job.entry, engagement_path))
        launched = made_up(job, pins, out_dir)
        lines = launched.recording.read_text().splitlines()
        started = json.loads(lines[0])
        started["authorization"]["engagement"] = {
            "engagement_id_declared": "acme-2026-10",
            "engagement_digest": digest,
            "window_declared": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
        }
        lines[0] = json.dumps(started)
        launched.recording.write_text("\n".join(lines) + "\n")
        return launched

    launch.handed = handed
    return launch


def run_under(tmp_path, loaded, launch, *, manifest=None, store_path=None):
    with Store.open(store_path or tmp_path / "s.sqlite") as store:
        return fleet.run(manifest or pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                         launcher=launch, engagement=loaded, now=NOW)  # fmt: skip


# -- refused before anything starts ----------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "condition"),
    [
        ({"targets": [{"host": "mcp.example.test", "paths": ["/mcp"]}]}, "target_not_listed"),
        ({"targets": [{"host": "localhost", "isolation": "runsc"}]}, "below_isolation"),
        ({"scenarios": []}, "scenario_not_listed"),
        ({"actions": {"list": False, "call": False}}, "lists_not_permitted"),
        ({"window": {"from": "2026-11-01T00:00:00Z", "until": "2026-11-07T18:00:00Z"}},
         "before_window"),
        ({"customer": "[CUSTOMER NAME]"}, "draft"),
    ],
)  # fmt: skip
def test_a_fleet_the_file_does_not_cover_is_refused_whole(tmp_path, changes, condition):
    loaded = engagement.load(engagement_file(tmp_path, **changes))
    with Store.open(tmp_path / "s.sqlite") as store:
        with pytest.raises(FleetError) as raised:
            fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=_never,
                      engagement=loaded, now=NOW)  # fmt: skip
        assert store.fleets() == []
        assert store.engagement() is None, "nothing set in the store either"
    assert raised.value.condition == condition
    words = str(raised.value)
    assert str(loaded.source) in words and "all-signals" in words and condition in words
    assert not (tmp_path / "runs").exists(), "no fleet directory, no fleet.json"


def test_a_job_the_fleet_refuses_anyway_is_not_held_to_the_file(tmp_path):
    """A real-world entry stays a refused result; the file, which lists nothing it could run
    under, is not asked about it."""
    manifest = write_manifest(
        tmp_path,
        {"name": "reference-server", "provenance": "reference", "server": REFERENCE},
        {"name": "outside", "provenance": "real-world"},
    )
    loaded = engagement.load(engagement_file(tmp_path))
    launch = launcher_under(loaded.digest)
    record = run_under(tmp_path, loaded, launch, manifest=manifest)
    assert record.results[("outside", "all-signals")].state == fleet.REFUSED
    assert [entry for entry, _ in launch.handed] == ["reference-server"]


def test_a_store_holding_another_engagement_refuses_the_fleet_before_any_launch(tmp_path):
    loaded = engagement.load(engagement_file(tmp_path))
    with Store.open(tmp_path / "s.sqlite") as store:
        store.set_engagement(engagement_id_declared="other-2026-09", digest="f0" * 32,
                             file_declared={"id": "other-2026-09"}, supersedes=None,
                             delete_after_declared=None, removed=(), now=NOW)  # fmt: skip
        with pytest.raises(FleetError, match="the store refused the engagement") as raised:
            fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=_never,
                      engagement=loaded, now=NOW)  # fmt: skip
        assert store.fleets() == []
    assert raised.value.condition is None
    assert not (tmp_path / "runs").exists()


def test_a_fleet_without_a_file_into_an_engagements_store_is_refused_before_any_launch(tmp_path):
    loaded = engagement.load(engagement_file(tmp_path))
    with Store.open(tmp_path / "s.sqlite") as store:
        store.set_engagement(engagement_id_declared=loaded.id, digest=loaded.digest,
                             file_declared=loaded.sanitized(), supersedes=None,
                             delete_after_declared="2027-01-31", removed=loaded.removed,
                             now=NOW)  # fmt: skip
        with pytest.raises(FleetError) as raised:
            fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=_never)
        assert store.fleets() == []
    words = str(raised.value)
    assert "acme-2026-10" in words and loaded.digest in words and "--engagement" in words
    assert not (tmp_path / "runs").exists()


# -- handed on, and held against what was filed ------------------------------------------------


def test_every_run_is_handed_the_file_by_its_absolute_path(tmp_path, monkeypatch):
    loaded = engagement.load(engagement_file(tmp_path))
    launch = launcher_under(loaded.digest)
    record = run_under(tmp_path, loaded, launch)
    assert record.complete, record.problems
    assert sorted(launch.handed) == [
        ("poison-server", Path(loaded.source)),
        ("reference-server", Path(loaded.source)),
    ]
    # And launch puts it into each child's argv, absolute even when given relative.
    seen = []

    class Done:
        pid = -1
        returncode = 0

        def communicate(self, timeout=None):
            return b"", b""

    monkeypatch.setattr(fleet.subprocess, "Popen", lambda argv, **_: seen.append(argv) or Done())
    monkeypatch.chdir(tmp_path)
    job = fleet.plan(fleet.load_manifest(pair(tmp_path)))[0]
    fleet.launch(job, PINS, tmp_path / "manifest.json", tmp_path / "out", step_timeout=2.0,
                 job_timeout=9.0, engagement_path=Path("engagement.json"))  # fmt: skip
    fleet.launch(job, PINS, tmp_path / "manifest.json", tmp_path / "out2", step_timeout=2.0,
                 job_timeout=9.0)  # fmt: skip
    with_file, without = seen
    given = with_file[with_file.index("--engagement") + 1]
    assert Path(given).is_absolute() and Path(given) == tmp_path / "engagement.json"
    assert "--engagement" not in without


def test_the_store_becomes_the_engagements(tmp_path):
    loaded = engagement.load(engagement_file(tmp_path))
    run_under(tmp_path, loaded, launcher_under(loaded.digest))
    with Store.open(tmp_path / "s.sqlite") as store:
        held = store.engagement()
    assert held["engagement_id_declared"] == "acme-2026-10"
    assert held["engagement_digest"] == loaded.digest
    assert held["delete_after_declared"] == "2027-01-31"
    (entry,) = held["chain"]
    assert "contacts" not in entry["file_declared"] and "reference" not in entry["file_declared"]


def test_a_filed_run_under_another_version_of_the_file_is_a_problem(tmp_path):
    """The earlier version is in the store's chain, so its runs are filed; they are still not
    runs under this fleet's file."""
    first = engagement.load(engagement_file(tmp_path, "first.json"))
    second = engagement.load(engagement_file(tmp_path, "second.json", supersedes=first.digest))
    with Store.open(tmp_path / "s.sqlite") as store:
        store.set_engagement(engagement_id_declared=first.id, digest=first.digest,
                             file_declared=first.sanitized(), supersedes=None,
                             delete_after_declared="2027-01-31", removed=first.removed,
                             now=NOW)  # fmt: skip
    record = run_under(tmp_path, second, launcher_under(first.digest))
    assert not record.complete
    for result in record.results.values():
        assert result.run is not None, "filed: the digest is in the chain"
        assert any(f"engagement file {first.digest}, not the fleet's" in p for p in result.problems)
    assert len([p for p in record.problems if "engagement file" in p]) == 2


# -- fleet.json --------------------------------------------------------------------------------


def test_fleet_json_names_the_file_as_a_recording_does_and_nothing_else(tmp_path):
    loaded = engagement.load(engagement_file(tmp_path))
    record = run_under(tmp_path, loaded, launcher_under(loaded.digest))
    (written,) = (tmp_path / "runs").glob("*/fleet.json")
    on_disk = json.loads(written.read_text())
    assert on_disk["engagement"] == {
        "engagement_id_declared": "acme-2026-10",
        "engagement_digest": loaded.digest,
        "window_declared": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
    }
    assert on_disk == json.loads(json.dumps(record.to_dict()))
    text = written.read_text()
    for value in ("ACME Corp", "SOW-17", "Dana", "customer_id", "2027-01-31"):
        assert value not in text


def test_without_a_file_fleet_json_says_null(tmp_path):
    from test_fleet import launcher

    with Store.open(tmp_path / "s.sqlite") as store:
        fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                  launcher=launcher({"reference-server": {}, "poison-server": {}}))  # fmt: skip
    (written,) = (tmp_path / "runs").glob("*/fleet.json")
    assert json.loads(written.read_text())["engagement"] is None


def test_the_engagement_enters_neither_the_digest_nor_the_comparison_nor_the_row(tmp_path):
    loaded = engagement.load(engagement_file(tmp_path))
    with_file = run_under(tmp_path, loaded, launcher_under(loaded.digest))
    without = fleet.FleetRun(**{**vars(with_file), "engagement": None})
    assert without.canonical() == with_file.canonical()
    assert without.digest == with_file.digest
    assert fleet._fleet_row(without) == fleet._fleet_row(with_file)
    # A second fleet under the same file: compared exactly as two fleets without one are.
    second = run_under(tmp_path, loaded, launcher_under(loaded.digest))
    with Store.open(tmp_path / "s.sqlite") as store:
        compared = fleet.compare(store, with_file.fleet, second.fleet)
    plain = tmp_path / "plain"
    plain.mkdir()
    from test_fleet import launcher

    with Store.open(plain / "s.sqlite") as store:
        runs = [
            fleet.run(pair(plain), store, plain / "runs", pins=PINS,
                      launcher=launcher({"reference-server": {}, "poison-server": {}}))
            for _ in range(2)
        ]  # fmt: skip
        compared_plain = fleet.compare(store, runs[0].fleet, runs[1].fleet)
    assert _without_ids(compared) == _without_ids(compared_plain)


def _without_ids(compared):
    """A comparison with the fleet and run ids, which differ between any two stores, taken out."""
    text = json.dumps(compared, sort_keys=True)
    return json.loads(text, object_hook=lambda d: {k: v for k, v in d.items()
                                                    if k not in ("fleet", "before", "after", "run",
                                                                 "runs", "manifest")})  # fmt: skip


def test_neither_a_mask_pattern_nor_an_owner_contact_reaches_the_store(tmp_path):
    """The literal strings to blank before a handover, and the customer's contact for a server,
    stay out of the chain; the chain says what was taken out."""
    loaded = engagement.load(
        engagement_file(
            tmp_path,
            redaction={"mask_keys": ["customer_id"], "mask_patterns": ["CANARY-PATTERN-1"]},
            declared={"servers": [{"name": "billing", "owner_contact": "CANARY-OWNER-2"}]},
        )
    )
    run_under(tmp_path, loaded, launcher_under(loaded.digest))
    raw = (tmp_path / "s.sqlite").read_bytes()
    for canary in (b"CANARY-PATTERN-1", b"CANARY-OWNER-2", b"Dana", b"SOW-17"):
        assert canary not in raw
    with Store.open(tmp_path / "s.sqlite") as store:
        (entry,) = store.engagement()["chain"]
    assert (
        entry["removed"]
        == list(loaded.removed)
        == [
            "contacts",
            "reference",
            "redaction.mask_patterns",
            "declared.servers[].owner_contact",
            "identities[].token_file",
            "known_values",
            "emergency",
            "salt_env",
            "receiver.key_env",
            "receiver.ssh",
            "receiver.path_prefix",
            "agency.contacts",
        ]
    )
    assert entry["file_declared"]["redaction"] == {"mask_keys": ["customer_id"]}
    assert entry["file_declared"]["declared"] == {"servers": [{"name": "billing"}]}


def test_fleet_json_s_engagement_block_reads_back(tmp_path):
    loaded = engagement.load(engagement_file(tmp_path))
    record = run_under(tmp_path, loaded, launcher_under(loaded.digest))
    (written,) = (tmp_path / "runs").glob("*/fleet.json")
    on_disk = json.loads(written.read_text())
    assert fleet.recorded_engagement(on_disk) == engagement.declaration_fields(loaded)
    assert fleet.recorded_engagement(record.to_dict()) == record.engagement
    assert fleet.recorded_engagement({**on_disk, "engagement": None}) is None
    before_the_field = {k: v for k, v in on_disk.items() if k != "engagement"}
    assert fleet.recorded_engagement(before_the_field) is None


GOOD_BLOCK = {
    "engagement_id_declared": "acme-2026-10",
    "engagement_digest": "ab" * 32,
    "window_declared": {"from": "2026-10-27T06:00:00Z", "until": "2026-11-07T18:00:00Z"},
}


@pytest.mark.parametrize(
    "block",
    [
        "acme-2026-10",
        {**GOOD_BLOCK, "customer": "ACME Corp"},
        {k: v for k, v in GOOD_BLOCK.items() if k != "window_declared"},
        {**GOOD_BLOCK, "engagement_id_declared": ""},
        {**GOOD_BLOCK, "engagement_digest": "AB" * 32},
        {**GOOD_BLOCK, "engagement_digest": "sha256:" + "ab" * 32},
        {**GOOD_BLOCK, "window_declared": None},
        {**GOOD_BLOCK, "window_declared": {"from": "2026-10-27T06:00:00Z"}},
        {**GOOD_BLOCK, "window_declared": {"from": "2026-10-27T06:00:00+00:00",
                                           "until": "2026-11-07T18:00:00Z"}},
    ],
)  # fmt: skip
def test_an_engagement_block_that_is_not_one_is_refused_whole(block):
    assert fleet.recorded_engagement({"engagement": GOOD_BLOCK}) == GOOD_BLOCK
    with pytest.raises(FleetError):
        fleet.recorded_engagement({"engagement": block})
