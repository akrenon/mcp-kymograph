"""``engagement status``: what an engagement has done so far, counted from the store and the
refusals files, and nothing of a finding but its count.

The store is built the way an operator builds one: real runs driven under an engagement file
through ``cli.main(["drive", …])`` against the corpus fixtures, then ``store ingest
--engagement``. One run is cut short to be incomplete, one is a server that never answers, and
one is filed as a real-world entry's, so every count the status gives has something behind it.
"""

import json
import os
import re
import shutil
import socket
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement, report, verdict
from mcp_kymograph.corpus import PROVENANCES
from mcp_kymograph.masking import Masker
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIO = FIXTURES / "scenarios" / "all-signals.yaml"
OTHER_SCENARIO = FIXTURES / "scenarios" / "instruction-in-disguise.yaml"
MANIFEST = FIXTURES / "corpus" / "manifest.yaml"

#: The moment the fixture's window is laid around: it opened a day before, closes three after.
NOW = datetime.now(timezone.utc).replace(microsecond=0)

SILENT_SERVER = "import sys\nsys.exit(3)\n"


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_engagement(directory: Path, **changes) -> Path:
    """An engagement file whose window holds :data:`NOW`, covering the local child, listing the
    fixtures' ``all-signals`` and ``instruction-in-disguise`` scenarios (copied beside it)."""
    directory.mkdir(parents=True, exist_ok=True)
    listed = []
    for source in (SCENARIO, OTHER_SCENARIO):
        shutil.copyfile(source, directory / source.name)
        digest = sha256((directory / source.name).read_bytes()).hexdigest()
        listed.append({"path": source.name, "sha256": digest})
    data = {
        "version": 1,
        "id": "acme-2026-10",
        "contacts": [{"name": "Dana", "role": "security lead", "reach": "phone"}],
        "window": {"from": utc(NOW - timedelta(days=1)), "until": utc(NOW + timedelta(days=3))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": listed,
        "actions": {"list": True, "call": False},
    }
    data.update(changes)
    path = directory / "engagement.json"
    path.write_text(json.dumps(data, indent=2))
    return path


def write_manifest(directory: Path) -> Path:
    """A manifest beside the engagement: a server that exits at once (``silent-server``), one
    that runs a listed scenario never driven here (``unrun-server``), and one whose only
    scenario the engagement does not list (``unlisted-server``)."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "silent.py").write_text(SILENT_SERVER)
    for source in (SCENARIO, OTHER_SCENARIO, FIXTURES / "scenarios" / "tool-poisoning.yaml"):
        shutil.copyfile(source, directory / source.name)
    entry = (
        "  - name: {name}\n    provenance: reference\n    source:\n      paths: [silent.py]\n"
        "    launch:\n      transport: stdio\n      command: ['{{python}}', '{{dir}}/silent.py']\n"
        "    scenarios: [{scenario}]\n"
    )
    path = directory / "manifest.yaml"
    path.write_text(
        "version: 1\nentries:\n"
        + entry.format(name="silent-server", scenario=SCENARIO.name)
        + entry.format(name="unrun-server", scenario=OTHER_SCENARIO.name)
        + entry.format(name="unlisted-server", scenario="tool-poisoning.yaml")
    )
    return path


def drive(held: Path, out_dir: Path, manifest: Path, entry: str) -> Path:
    before = set(out_dir.iterdir()) if out_dir.exists() else set()
    cli.main(
        ["drive", "-q", "--engagement", str(held), "--manifest", str(manifest), "--entry", entry,
         "--isolation", "host", "--out-dir", str(out_dir)]
    )  # fmt: skip
    (run,) = set(out_dir.iterdir()) - before
    return run / "events.jsonl"


def copy_recording(recording: Path, to: Path, change) -> Path:
    """A copy of a recording, its text changed: what a run of another kind would have left."""
    to.mkdir(parents=True)
    copied = to / "events.jsonl"
    copied.write_text(change(recording.read_text()))
    return copied


@pytest.fixture(scope="module")
def filed(tmp_path_factory):
    """A store of one engagement holding runs of several states, and what it was built from."""
    root = tmp_path_factory.mktemp("status")
    held = write_engagement(root / "engagement")
    manifest = write_manifest(root / "engagement")
    out_dir = root / "runs"
    recordings = [
        drive(held, out_dir, MANIFEST, "reference-server"),
        drive(held, out_dir, MANIFEST, "poison-server"),
        drive(held, out_dir, manifest, "silent-server"),
    ]
    poison = recordings[1]
    copies = root / "copies"
    # Cut short before its last line: the run's end is missing, and it is not a result.
    recordings.append(
        copy_recording(poison, copies / "cut", lambda text: "".join(text.splitlines(True)[:-1]))
    )
    # Filed as a real-world entry's: the same content under another name and provenance.
    recordings.append(
        copy_recording(
            poison,
            copies / "wild",
            lambda text: text.replace('"poison-server"', '"wild-server"').replace(
                '"provenance": "poison"', '"provenance": "real-world"'
            ),
        )
    )
    database = root / "findings.sqlite"
    assert cli.main(
        ["store", "ingest", "-q", "--store", str(database), "--engagement", str(held),
         *map(str, recordings)]
    ) in (0, 3, 4)  # fmt: skip
    with Store.open_read_only(database) as store:
        states = Counter(run.state for run in store.runs())
    assert states == {"complete": 3, "incomplete": 1, "server_failed": 1}, states
    return {"held": held, "manifest": manifest, "database": database, "root": root}


def status_of(filed, **options) -> report.Status:
    with Store.open_read_only(filed["database"]) as store:
        return report.status(store, now=options.pop("now", NOW), **options)


def all_findings(database: Path) -> list[dict]:
    with Store.open_read_only(database) as store:
        return [key for p in PROVENANCES for key in store.findings_by_provenance(p)]


# -- the counts -------------------------------------------------------------------------------


def test_the_engagement_and_its_window_come_from_the_store(filed):
    result = status_of(filed)
    loaded = engagement.load(filed["held"])

    assert result.engagement_id_declared == "acme-2026-10"
    assert result.engagement_digest == loaded.digest
    assert result.engagement_source == "store"
    assert result.versions == 1
    assert (result.window_from, result.window_until) == (
        loaded.window_declared()["from"],
        loaded.window_declared()["until"],
    )
    assert result.window == report.Window("open", 3 * 86400)
    text = report.render_status(result)
    assert f"Engagement acme-2026-10 (version 1 of 1, SHA-256 {loaded.digest})." in text
    assert "open, 3 days left" in text


@pytest.mark.parametrize(
    ("now", "words"),
    [
        (NOW - timedelta(days=3), "opens in 2 days"),
        (NOW + timedelta(days=5), "closed 2 days ago"),
        (NOW + timedelta(days=3) - timedelta(hours=5), "open, 5 hours left"),
        (NOW + timedelta(days=3) - timedelta(minutes=5), "open, less than an hour left"),
    ],
)
def test_where_now_stands_against_the_window(filed, now, words):
    assert words in report.render_status(status_of(filed, now=now))


def test_runs_are_counted_by_state_and_every_state_is_named(filed):
    result = status_of(filed)
    with Store.open_read_only(filed["database"]) as store:
        counted = Counter(run.state for run in store.runs())

    assert result.runs_by_state == {state: counted.get(state, 0) for state in verdict.STATES}
    assert list(result.runs_by_state) == list(report.RUN_STATES)
    text = report.render_status(result)
    assert (
        "Runs filed: 5 — 3 complete; not results: 0 sandbox_failed, 1 server_failed, "
        "1 incomplete, 0 call_failed." in text
    )


def test_findings_are_counted_by_entry_and_real_world_ones_apart(filed):
    result = status_of(filed)
    by_entry = {entry.entry: entry for entry in result.entries}
    findings = all_findings(filed["database"])
    poison = sum(1 for key in findings if key["server"] == "poison-server")
    wild = sum(1 for key in findings if key["server"] == "wild-server")
    assert poison > 0 and wild == poison

    assert by_entry["poison-server"] == report.EntryCount(
        "poison-server", "poison", runs=2, complete_runs=1, findings=poison,
        findings_in_complete=poison,
    )  # fmt: skip
    assert by_entry["reference-server"].findings == 0
    assert by_entry["silent-server"] == report.EntryCount(
        "silent-server", "reference", runs=1, complete_runs=0, findings=0, findings_in_complete=0
    )
    assert by_entry["wild-server"].provenance == "real-world"
    text = report.render_status(result)
    (ordinary,) = [line for line in text.splitlines() if line.startswith("Findings by entry")]
    (candidates,) = [line for line in text.splitlines() if line.startswith("Real-world")]
    assert "wild-server" not in ordinary
    assert f"poison-server (poison) {poison} findings in 2 runs, 1 of them complete" in ordinary
    assert "candidates for responsible disclosure" in candidates
    assert f"wild-server (real-world) {wild} candidates in 1 run" in candidates


def test_the_status_holds_no_locator_no_signal_and_nothing_the_server_sent(filed):
    findings = all_findings(filed["database"])
    assert findings
    result = status_of(filed, manifest=filed["manifest"], out_dir=filed["root"] / "runs")
    shown = [report.render_status(result), json.dumps(result.to_dict())]

    for key in findings:
        quoted = re.findall(r'"([^"]+)"', key["locator"])
        for value in (key["locator"], key["signal"], key["statement"], *quoted):
            for text in shown:
                assert value not in text, value


# -- refusals ---------------------------------------------------------------------------------


def refuse(out_dir: Path, held: engagement.Engagement, reason: str, when: datetime) -> None:
    written = engagement.record_refusal(
        out_dir,
        argv=["drive", "--engagement", "engagement.json"],
        masker=Masker(),
        reason=reason,
        message=f"refused for {reason}",
        engagement=held,
        now=when,
    )
    assert written is None


def test_fleet_jobs_without_a_run_are_counted_from_the_store(filed, tmp_path):
    database = tmp_path / "findings.sqlite"
    shutil.copyfile(filed["database"], database)
    fleet = {
        "fleet": "f1", "started_utc": "2026-10-28T09:00:00.000+00:00",
        "finished_utc": "2026-10-28T09:01:00.000+00:00", "manifest_source": "m.yaml",
        "manifest_digest": "sha256:" + "33" * 32, "tool_version": "t",
        "tool_content": "sha256:" + "11" * 32, "isolation": "host", "sandbox_image": None,
        "target_image": None, "parallel": 1, "processed": "[]", "digest": "f" * 64,
        "complete": 0, "problems": "[]", "rules": verdict.RULES_VERSION,
    }  # fmt: skip
    results = [
        {"entry": name, "scenario": "all-signals", "provenance": "reference", "state": state,
         "exit_code": 2, "run": None, "problems": ["refused before it started"]}
        for name, state in (("a", "refused"), ("b", "refused"), ("c", "unfiled"))
    ]  # fmt: skip
    with Store.open(database) as store:
        store.file_fleet(fleet, results)
    with Store.open_read_only(database) as store:
        result = report.status(store, now=NOW)

    assert result.fleet_results == {"refused": 2, "unfiled": 1}
    assert sum(result.runs_by_state.values()) == 5, "a fleet job without a run is no run"
    assert (
        "Fleet jobs with no run filed: 2 refused, 1 unfiled (the store's fleet results)."
        in report.render_status(result)
    )
    assert status_of(filed).fleet_results == {}


def test_without_an_out_dir_refusals_were_not_looked_at(filed):
    result = status_of(filed)

    assert result.refusals_out_dir is None
    assert "Refusals: not looked at — no out-dir was given." in report.render_status(result)


def test_refusals_are_counted_by_reason_and_another_file_s_apart(filed, tmp_path):
    held = engagement.load(filed["held"])
    other = engagement.load(write_engagement(tmp_path / "other", id="other-2026-11"))
    out_dir = tmp_path / "out"
    refuse(out_dir, held, "after_window", NOW)
    refuse(out_dir, held, "after_window", NOW)
    refuse(out_dir, held, "manifest", NOW - timedelta(days=2))
    refuse(out_dir / "fleet" / "001-poison-server", held, "below_isolation", NOW)
    refuse(out_dir, other, "draft", NOW)

    result = status_of(filed, out_dir=out_dir)

    assert [item.path for item in result.refusal_files] == [
        "fleet/001-poison-server/refusals.jsonl",
        "refusals.jsonl",
    ]
    top = result.refusal_files[1]
    assert top.by_reason == {"after_window": 2, "manifest": 1}
    assert (top.other_engagement, top.outside_window, top.near_cap) == (1, 1, False)
    assert result.exit_code == 0
    text = report.render_status(result)
    assert (
        "Refusals under this engagement: 4 in 2 files — 2 after_window, 1 below_isolation, "
        "1 manifest; 1 of them outside the window of the version they name; 1 more naming a "
        "file digest that is not in this store's chain, not counted here." in text
    )
    assert "refused for" not in text, "the refusal's message stays in the file"


def test_an_unreadable_refusals_file_is_named_not_skipped(filed, tmp_path):
    out_dir = tmp_path / "out"
    refuse(out_dir, engagement.load(filed["held"]), "manifest", NOW)
    broken = out_dir / "fleet" / "002-x" / engagement.REFUSALS_FILE
    broken.parent.mkdir(parents=True)
    broken.write_text("not a refusal\n")

    result = status_of(filed, out_dir=out_dir)

    (unreadable,) = result.refusals_unreadable
    assert unreadable.path == "fleet/002-x/refusals.jsonl"
    assert result.exit_code == report.EXIT_UNREAD
    text = report.render_status(result)
    assert "Refusals under this engagement: 1 in 1 file — 1 manifest." in text
    assert (
        "Unreadable, not counted: fleet/002-x/refusals.jsonl "
        f"({report.REFUSED_BY_THE_READER})." in text
    )
    (listed,) = [
        item for item in result.to_dict()["refusal_files"] if item["path"] == unreadable.path
    ]
    assert listed["unreadable"] == report.REFUSED_BY_THE_READER
    assert listed["reason"].startswith("line 1: "), "the reader's reason, in the JSON only"
    assert listed["reason"] not in text


def test_each_refusal_is_held_against_the_window_of_the_version_it_names(filed, tmp_path):
    database = tmp_path / "findings.sqlite"
    shutil.copyfile(filed["database"], database)
    first = engagement.load(filed["held"])
    # The second version's window opens a day after NOW: a refusal under the first version at
    # NOW lies inside its own window, and one under the second at NOW outside the second's.
    second = engagement.load(
        write_engagement(
            tmp_path / "second",
            supersedes=first.digest,
            window={"from": utc(NOW + timedelta(days=1)), "until": utc(NOW + timedelta(days=5))},
        )
    )
    with Store.open(database) as store:
        store.set_engagement(
            engagement_id_declared=second.id, digest=second.digest,
            file_declared=second.sanitized(), supersedes=first.digest,
            delete_after_declared=None, removed=second.removed,
        )  # fmt: skip
    stranger = engagement.load(write_engagement(tmp_path / "stranger", id="stranger-2026-12"))
    out_dir = tmp_path / "out"
    refuse(out_dir, first, "manifest", NOW)
    refuse(out_dir, second, "before_window", NOW)
    refuse(out_dir, stranger, "draft", NOW)

    with Store.open_read_only(database) as store:
        result = report.status(store, out_dir=out_dir, now=NOW)

    (counted,) = result.refusal_files
    assert counted.by_reason == {"before_window": 1, "manifest": 1}
    assert counted.outside_window == 1, "the first version's refusal lies inside its own window"
    assert counted.other_engagement == 1
    assert "not in this store's chain" in report.render_status(result)


def fill_to_room(out_dir: Path, held: Path, room: int, *, at_most: bool) -> Path:
    """A refusals file of real refusal lines whose room below the cap is at most ``room`` bytes
    (``at_most``), or at least ``room`` bytes."""
    refuse(out_dir, engagement.load(held), "manifest", NOW)
    path = out_dir / engagement.REFUSALS_FILE
    line = path.read_bytes()
    needed = engagement.MAX_REFUSALS_BYTES - room
    lines = -(-needed // len(line)) if at_most else needed // len(line)
    path.write_bytes(line * lines)
    return path


def test_little_room_below_the_cap_is_said_as_room_and_never_as_a_drop(filed, tmp_path):
    out_dir = tmp_path / "out"
    path = fill_to_room(out_dir, filed["held"], report.REFUSALS_ROOM_SAID - 1, at_most=True)

    result = status_of(filed, out_dir=out_dir)

    (counted,) = result.refusal_files
    room = engagement.MAX_REFUSALS_BYTES - path.stat().st_size
    assert counted.room_bytes == room < report.REFUSALS_ROOM_SAID
    assert counted.near_cap and counted.unreadable is None
    text = report.render_status(result)
    assert (
        f"refusals.jsonl: {room} bytes left below the cap of {engagement.MAX_REFUSALS_BYTES}; "
        "a refusal longer than that cannot be written now." in text
    )
    assert "apped" not in text and "missing" not in text


def test_room_enough_below_the_cap_is_not_said(filed, tmp_path):
    out_dir = tmp_path / "out"
    path = fill_to_room(out_dir, filed["held"], report.REFUSALS_ROOM_SAID, at_most=False)

    result = status_of(filed, out_dir=out_dir)

    (counted,) = result.refusal_files
    assert counted.room_bytes == engagement.MAX_REFUSALS_BYTES - path.stat().st_size
    assert counted.room_bytes >= report.REFUSALS_ROOM_SAID
    assert not counted.near_cap
    assert "bytes left below the cap" not in report.render_status(result)


def test_an_out_dir_without_refusals_says_none_were_recorded(filed, tmp_path):
    result = status_of(filed, out_dir=tmp_path)

    assert result.refusal_files == ()
    assert "Refusals: none recorded; no refusals.jsonl under the out-dir." in (
        report.render_status(result)
    )


def test_an_out_dir_that_is_not_a_directory_is_refused(filed, tmp_path):
    with pytest.raises(engagement.EngagementError, match="not a directory"):
        status_of(filed, out_dir=filed["held"])


# -- what is still planned --------------------------------------------------------------------


def test_planned_without_a_manifest_is_each_listed_scenario_without_a_complete_run(filed):
    result = status_of(filed)

    assert result.plannable == 2
    (planned,) = result.planned
    assert (planned.entry, planned.scenario_path, planned.states) == (
        None,
        OTHER_SCENARIO.name,
        {},
    )
    text = report.render_status(result)
    assert (
        "Still planned: 1 of 2 listed scenarios have no complete run: "
        f"{OTHER_SCENARIO.name}." in text
    )
    assert "give --manifest for them" in text


def test_planned_with_a_manifest_is_each_listed_pair_without_a_complete_run(filed):
    result = status_of(filed, manifest=filed["manifest"])

    assert result.plannable == 2, "the unlisted entry's scenario is not the engagement's"
    assert [(p.entry, p.scenario_path, p.states) for p in result.planned] == [
        ("silent-server", SCENARIO.name, {"server_failed": 1}),
        ("unrun-server", OTHER_SCENARIO.name, {}),
    ]
    text = report.render_status(result)
    assert (
        f"silent-server × {SCENARIO.name} (1 run, none complete: 1 server_failed); "
        f"unrun-server × {OTHER_SCENARIO.name}." in text
    )
    assert "give --manifest" not in text


def test_a_complete_run_of_the_pair_takes_it_off_the_plan(filed):
    result = status_of(filed, manifest=MANIFEST)

    assert (result.plannable, result.planned) == (2, ())
    assert "Still planned: 0 of 2 (entry, scenario) pairs" in report.render_status(result)


# -- the engagement, or none ------------------------------------------------------------------


def test_a_store_without_an_engagement_says_so(tmp_path):
    with Store.open(tmp_path / "empty.sqlite") as store:
        result = report.status(store, now=NOW)

    assert result.engagement_digest is None
    assert result.exit_code == report.EXIT_UNREAD
    text = report.render_status(result)
    assert text.startswith("This store holds no engagement")
    assert "Still planned: not known" in text
    assert "Findings: no reference or poison entry has a run filed." in text
    assert "Real-world entries: none has a run filed." in text


def test_an_empty_store_with_the_file_reads_the_window_from_the_file(tmp_path):
    held = engagement.load(write_engagement(tmp_path / "engagement"))
    with Store.open(tmp_path / "empty.sqlite") as store:
        result = report.status(store, engagement=held, now=NOW)

    assert (result.engagement_source, result.engagement_digest) == ("file", held.digest)
    assert result.plannable == 2 and len(result.planned) == 2
    assert "the store holds no engagement yet" in report.render_status(result)


def test_a_file_that_is_not_a_version_of_the_store_s_is_refused(filed, tmp_path):
    other = engagement.load(write_engagement(tmp_path / "other", id="other-2026-11"))

    with pytest.raises(report.ReportError, match="not among the store's versions"):
        status_of(filed, engagement=other)


def test_the_status_reads_the_store_and_changes_nothing(filed, tmp_path):
    before = filed["database"].read_bytes(), os.stat(filed["database"]).st_mode
    status_of(filed, manifest=filed["manifest"], out_dir=filed["root"] / "runs")
    assert (filed["database"].read_bytes(), os.stat(filed["database"]).st_mode) == before


def test_to_dict_round_trips_through_json(filed, tmp_path):
    out_dir = tmp_path / "out"
    refuse(out_dir, engagement.load(filed["held"]), "manifest", NOW)
    result = status_of(filed, manifest=filed["manifest"], out_dir=out_dir)

    written = result.to_dict()
    read = json.loads(json.dumps(written))

    assert read == written
    assert report.Status.from_dict(read) == result
    assert report.render_status(report.Status.from_dict(read)) == report.render_status(result)


def test_a_value_from_the_file_cannot_reach_the_terminal_raw(tmp_path):
    held = engagement.load(write_engagement(tmp_path / "engagement", id="acme-2026-10"))
    with Store.open(tmp_path / "empty.sqlite") as store:
        result = report.status(store, engagement=held, now=NOW)
    hostile = report.Status.from_dict(
        {**result.to_dict(), "engagement_id_declared": "acme\x1b[2J\u202eevil"}
    )

    text = report.render_status(hostile)

    assert "\x1b" not in text and "\u202e" not in text
    assert "acme[2Jevil" in text


def test_the_status_is_about_a_dozen_lines(filed, tmp_path):
    out_dir = tmp_path / "out"
    refuse(out_dir, engagement.load(filed["held"]), "manifest", NOW)
    text = report.render_status(status_of(filed, manifest=filed["manifest"], out_dir=out_dir))

    assert len(text.splitlines()) <= 12


# -- preflight --------------------------------------------------------------------------------


def no_image(reference: str) -> str:
    raise AssertionError(f"image_id was asked for {reference!r} although no image was given")


def preflight(path: Path, **options) -> report.Preflight:
    options.setdefault("image_id", no_image)
    return report.preflight(path, now=options.pop("now", NOW), **options)


def item(result: report.Preflight, name: str) -> report.Item:
    (found,) = [each for each in result.items if each.name == name]
    return found


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True)
    path.chmod(0o700)
    return path


def write_wild_manifest(directory: Path) -> Path:
    """A manifest whose one entry is real-world and runs a scenario the engagement lists."""
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SCENARIO, directory / SCENARIO.name)
    (directory / "wild.py").write_text(SILENT_SERVER)
    path = directory / "wild.yaml"
    path.write_text(
        "version: 1\nentries:\n  - name: wild-server\n    provenance: real-world\n"
        "    source:\n      paths: [wild.py]\n    launch:\n      transport: stdio\n"
        "      command: ['{python}', '{dir}/wild.py']\n"
        f"    scenarios: [{SCENARIO.name}]\n"
    )
    return path


def test_preflight_with_nothing_but_the_file_checks_what_it_can_and_says_what_it_did_not(
    tmp_path,
):
    result = preflight(write_engagement(tmp_path / "engagement"))

    assert [each.name for each in result.items] == [
        "file", "scenarios", "manifest", "isolation", "sandbox image", "target image",
        "endpoints", "store", "out-dir", "client templates", "contacts", "canaries", "salt",
        "receiver key",
    ]  # fmt: skip
    states = {each.name: each.state for each in result.items}
    assert states == {
        "file": "ready", "scenarios": "ready", "manifest": "not_checked", "isolation": "ready",
        "sandbox image": "not_checked", "target image": "not_checked", "endpoints": "ready",
        "store": "not_checked", "out-dir": "not_checked", "client templates": "not_checked",
        "contacts": "ready", "canaries": "not_checked", "salt": "not_checked",
        "receiver key": "not_checked",
    }  # fmt: skip
    assert result.ready and result.exit_code == report.EXIT_READY
    assert "docs/clients.md is documentation" in item(result, "client templates").words
    assert item(result, "manifest").words == "no --manifest given"


@pytest.mark.parametrize(
    ("start", "end", "state", "words"),
    [
        (NOW - timedelta(days=1), NOW + timedelta(days=3), "ready", "open now, until"),
        (NOW + timedelta(days=2), NOW + timedelta(days=5), "ready", "in 2 days, and closes at"),
        (NOW - timedelta(days=5), NOW - timedelta(days=2), "not_ready", "2 days ago"),
    ],
)
def test_the_file_item_follows_the_window(tmp_path, start, end, state, words):
    held = write_engagement(tmp_path / "e", window={"from": utc(start), "until": utc(end)})

    found = item(preflight(held), "file")

    assert (found.state, words in found.words) == (state, True), found.words


def test_a_draft_is_not_ready_and_its_placeholders_are_named(tmp_path):
    held = write_engagement(tmp_path / "e", customer="[CUSTOMER NAME]")

    found = item(preflight(held), "file")

    assert found.state == "not_ready"
    assert "placeholders at customer" in found.words


def test_a_file_the_reader_refuses_is_the_answer_not_an_item(tmp_path):
    held = write_engagement(tmp_path / "e", version=3)

    with pytest.raises(engagement.EngagementError, match="unsupported 3"):
        preflight(held)


def test_the_scenarios_item_says_what_the_reader_checked(tmp_path):
    listed = item(preflight(write_engagement(tmp_path / "a")), "scenarios")
    none = item(preflight(write_engagement(tmp_path / "b", scenarios=[])), "scenarios")

    assert listed.state == "ready" and "2 listed" in listed.words
    assert SCENARIO.name in listed.words and OTHER_SCENARIO.name in listed.words
    assert none.state == "ready" and none.words.startswith("none listed")


def test_the_manifest_item_names_its_pairs_and_its_refused_entries(tmp_path):
    held = write_engagement(tmp_path / "e")

    ready = item(preflight(held, manifest=MANIFEST), "manifest")
    wild = item(preflight(held, manifest=write_wild_manifest(tmp_path / "m")), "manifest")
    broken = item(preflight(held, manifest=tmp_path / "missing.yaml"), "manifest")
    mixed = item(preflight(held, manifest=write_manifest(tmp_path / "x")), "manifest")

    assert ready.state == "ready"
    assert f"reference-server × {SCENARIO.name}, poison-server × {SCENARIO.name}" in ready.words
    assert wild.state == "not_ready"
    assert (
        "wild-server (real-world) will be refused: this version does not provide runsc"
        in wild.words
    )
    assert broken.state == "not_ready" and "cannot be used" in broken.words
    assert mixed.state == "ready"
    assert "no scenario the file lists, so not run under it: unlisted-server" in mixed.words


def test_the_manifest_item_names_an_endpoint_entry_and_contacts_nothing(tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("preflight reached for the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    held = write_engagement(tmp_path / "e")
    manifest = tmp_path / "m" / "manifest.json"
    manifest.parent.mkdir()
    shutil.copyfile(SCENARIO, manifest.parent / SCENARIO.name)
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": {"endpoint": "http://127.0.0.1:8080/mcp"},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [SCENARIO.name],
                    }
                ],
            }
        )
    )

    found = item(preflight(held, manifest=manifest), "manifest")

    assert found.state == "ready", found.words
    assert (
        "customer-mcp is an endpoint entry: driven through drive only, under remote, never in a "
        "fleet; not contacted" in found.words
    )
    assert "will be refused" not in found.words


@pytest.mark.parametrize(
    ("url", "where"),
    [
        ("http://mcp.example.com:80/mcp", "mcp.example.com:80"),
        ("http://localhost:8080/mcp", "localhost:8080"),
    ],
)
def test_a_plain_http_endpoint_entry_on_another_host_will_be_refused(tmp_path, url, where):
    """Plain HTTP only to a loopback literal: the manifest reads such an entry, and preflight says
    it will be refused when it is run, with the words the run would print — localhost included,
    a name."""
    held = write_engagement(tmp_path / "e")
    manifest = tmp_path / "m" / "manifest.json"
    manifest.parent.mkdir()
    shutil.copyfile(SCENARIO, manifest.parent / SCENARIO.name)
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": {"endpoint": url},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [SCENARIO.name],
                    }
                ],
            }
        )
    )

    found = item(preflight(held, manifest=manifest), "manifest")

    assert found.state == "not_ready"
    assert f"customer-mcp will be refused: plain HTTP to {where}, which is not a loopback " in (
        found.words
    )
    assert "is an endpoint entry" not in found.words


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com:443/mcp",
        "https://localhost:8443/mcp",
        "https://127.0.0.2:8443/mcp",
    ],
)
def test_an_https_endpoint_entry_on_another_host_is_not_named_as_refused(tmp_path, url):
    """https:// is spoken to any host, so such an entry is ready, named an endpoint
    entry and not contacted; plain HTTP stays refused (above)."""
    held = write_engagement(tmp_path / "e")
    manifest = tmp_path / "m" / "manifest.json"
    manifest.parent.mkdir()
    shutil.copyfile(SCENARIO, manifest.parent / SCENARIO.name)
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": {"endpoint": url},
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [SCENARIO.name],
                    }
                ],
            }
        )
    )

    found = item(preflight(held, manifest=manifest), "manifest")

    assert found.state == "ready", found.words
    assert "customer-mcp is an endpoint entry" in found.words and "not contacted" in found.words
    assert "will be refused" not in found.words


def test_a_runsc_target_will_be_refused(tmp_path):
    held = write_engagement(
        tmp_path / "e",
        targets=[
            {"host": "127.0.0.1", "isolation": "runc"},
            {"host": "localhost", "isolation": "runsc"},
        ],
    )

    found = item(preflight(held), "isolation")

    assert found.state == "not_ready"
    assert found.words == (
        "targets[1] (localhost) will be refused: it requires runsc, and this version does not "
        "provide runsc"
    )


def test_images_are_looked_up_through_the_stand_in_only(tmp_path, monkeypatch):
    def no_docker(*args, **kwargs):
        raise AssertionError("docker was called directly")

    monkeypatch.setattr(report.docker, "run", no_docker)
    asked = []

    def image_id(reference: str) -> str:
        asked.append(reference)
        if reference == "missing:1":
            raise report.docker.DockerError("docker image: exit 1: No such image: missing:1")
        return "sha256:" + "a" * 64

    result = preflight(
        write_engagement(tmp_path / "e"),
        sandbox_image="sandbox:1",
        target_image="missing:1",
        image_id=image_id,
    )

    assert asked == ["sandbox:1", "missing:1"]
    assert item(result, "sandbox image") == report.Item(
        "sandbox image", "ready", f"sandbox:1 is present here as sha256:{'a' * 64}"
    )
    target = item(result, "target image")
    assert target.state == "not_ready" and "No such image: missing:1" in target.words
    assert result.exit_code == report.EXIT_NOT_READY


def test_an_endpoint_target_is_not_contacted_and_says_so(tmp_path):
    held = write_engagement(
        tmp_path / "e",
        targets=[{"host": "127.0.0.1"}, {"host": "mcp.example.com", "paths": ["/mcp"]}],
    )

    found = item(preflight(held), "endpoints")

    assert found == report.Item(
        "endpoints",
        "not_checked",
        "mcp.example.com: not contacted; whether it answers is found out by the first run "
        "inside the window, and recorded there",
    )


def test_the_store_item_in_each_of_its_states(filed, tmp_path):
    held = write_engagement(tmp_path / "e")
    other = write_engagement(tmp_path / "o", id="other-2026-11")
    places = private_directory(tmp_path / "stores")
    empty = places / "empty.sqlite"
    Store.open(empty).close()
    loose = places / "loose.sqlite"
    Store.open(loose).close()
    loose.chmod(0o644)
    garbage = places / "garbage.sqlite"
    garbage.write_bytes(b"not a store, whatever its name says")
    garbage.chmod(0o600)

    def state(path: Path, store: Path) -> report.Item:
        return item(preflight(path, store=store), "store")

    assert state(held, places / "new.sqlite").state == "ready"
    assert "not created yet" in state(held, places / "new.sqlite").words
    assert not (places / "new.sqlite").exists()
    assert state(held, empty) == report.Item("store", "ready", "an empty store")
    ours = state(filed["held"], filed["database"])
    assert ours.state == "ready"
    assert "holds this engagement (this file is version 1 of 1), 5 run(s) filed" in ours.words
    theirs = state(other, filed["database"])
    assert theirs.state == "not_ready"
    assert "holds another engagement, acme-2026-10" in theirs.words
    assert state(held, loose) == report.Item("store", "not_ready", "it has mode 0644, not 0600")
    assert state(held, garbage).state == "not_ready"
    assert "cannot be read as a store" in state(held, garbage).words
    nowhere = state(held, tmp_path / "nowhere" / "s.sqlite")
    assert nowhere.state == "not_ready" and "its directory cannot be read" in nowhere.words


def test_the_out_dir_item_in_each_of_its_states(tmp_path):
    held = write_engagement(tmp_path / "e")
    ready = private_directory(tmp_path / "ready")
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o755)
    full = private_directory(tmp_path / "full")
    (full / "something").write_text("")
    a_file = tmp_path / "a-file"
    a_file.write_text("")
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)  # noqa: S607
    committable = private_directory(repo / "runs")

    def state(path: Path) -> report.Item:
        return item(preflight(held, out_dir=path), "out-dir")

    assert state(ready) == report.Item(
        "out-dir", "ready", "exists, empty, mode 0700, not where recordings may be committed"
    )
    missing = state(tmp_path / "missing")
    assert missing.state == "not_ready"
    assert "does not exist; preflight creates nothing" in missing.words
    assert not (tmp_path / "missing").exists()
    assert state(loose) == report.Item("out-dir", "not_ready", "it has mode 0755, not 0700")
    assert "it holds 1 entry" in state(full).words
    assert state(a_file) == report.Item("out-dir", "not_ready", "it is not a directory")
    assert state(committable).state == "not_ready"
    assert "inside a git working tree" in state(committable).words


def test_the_contacts_item_wants_one_with_a_reach(tmp_path):
    without = write_engagement(tmp_path / "a", contacts=[{"name": "Dana"}])
    placeholder = write_engagement(tmp_path / "b", contacts=[{"name": "Dana", "reach": "[TEL]"}])
    no_one = write_engagement(tmp_path / "c")
    data = json.loads(no_one.read_text())
    del data["contacts"]
    no_one.write_text(json.dumps(data))

    assert item(preflight(without), "contacts") == report.Item(
        "contacts",
        "not_ready",
        "1 listed, none with a reach: nobody can be reached during the window",
    )
    assert item(preflight(placeholder), "contacts").state == "not_ready"
    assert item(preflight(no_one), "contacts").words.startswith("0 listed, none")


def tree(root: Path) -> dict[str, tuple[int, bytes | None]]:
    """Every path under ``root``: its mode, and its bytes if it is a file."""
    found = {}
    for path in sorted(root.rglob("*")):
        status = path.lstat()
        content = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        found[str(path.relative_to(root))] = (status.st_mode, content)
    return found


def test_preflight_connects_to_nothing_and_leaves_the_tree_as_it_was(filed, tmp_path, monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("preflight reached for the network")

    root = filed["root"]
    out_dir = private_directory(tmp_path / "out")
    before = tree(root), tree(tmp_path)
    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)

    result = preflight(
        filed["held"],
        manifest=filed["manifest"],
        store=filed["database"],
        out_dir=out_dir,
        sandbox_image="sandbox:1",
        target_image="target:1",
        image_id=lambda reference: "sha256:" + "b" * 64,
    )

    assert (tree(root), tree(tmp_path)) == before
    assert result.ready, report.render_preflight(result)
    assert result.exit_code == report.EXIT_READY


def test_preflight_to_dict_round_trips_and_renders_every_item(tmp_path):
    result = preflight(write_engagement(tmp_path / "e"), out_dir=tmp_path / "missing")

    written = result.to_dict()
    assert json.loads(json.dumps(written)) == written
    assert written["ready"] is False and result.exit_code == report.EXIT_NOT_READY
    assert [report.Item(**each) for each in written["items"]] == list(result.items)
    text = report.render_preflight(result)
    for each in result.items:
        assert each.name in text and each.state in text
    assert text.rstrip().endswith("Not ready: out-dir.")


def test_a_value_from_the_file_reaches_the_terminal_filtered(tmp_path):
    directory = tmp_path / "e"
    hostile = "evil\x1b[2J\N{RIGHT-TO-LEFT OVERRIDE}.yaml"
    directory.mkdir()
    (directory / hostile).write_bytes(SCENARIO.read_bytes())
    listed = [{"path": hostile, "sha256": sha256(SCENARIO.read_bytes()).hexdigest()}]
    held = write_engagement(directory, scenarios=listed)

    result = preflight(held)
    text = report.render_preflight(result)

    assert hostile in item(result, "scenarios").words
    assert "\x1b" not in text and "\N{RIGHT-TO-LEFT OVERRIDE}" not in text
    assert "evil[2J.yaml" in text


# -- preflight: the second version's canaries, salt and receiver key ---------------------------

# At least 32 characters: a salt shorter than that is not ready.
SALT_VALUE = "salt-" + "-".join(["value", "9f3a", "c41e07b2d86a5513e0f7"])


def write_second(directory: Path, **changes) -> Path:
    """The fixture file as a file of the second version, with what that version requires."""
    required = {
        "version": 2,
        "end_customer": {"name": "ACME Corp"},
        "abort_criteria": ["any write to production data"],
        "emergency": {"name": "Lee Ops", "reach": "+49 30 5550100"},
        "salt_env": "DEMO_SALT",
    }
    return write_engagement(directory, **(required | changes))


RECEIVER = {
    "variant": "reachable",
    "address": "recv.example.test",
    "path_prefix": "Zm9vYmFyYmF6cXV4MTIzNDU2",
    "key_env": "DEMO_RECEIVER_KEY",
    "retention_seconds": 3600,
}
CANARIES = [
    {"id": "c1", "kind": "tool_text", "where": "the search tool", "removed": None},
    {
        "id": "c2",
        "kind": "file",
        "where": "next to the server",
        "path": "/srv/outside/secret-place.txt",
        "removed": None,
    },
    {"id": "c3", "kind": "prompt", "where": "the greeting", "removed": "2026-11-03"},
]


def test_a_file_of_the_first_version_declares_none_of_the_three(tmp_path):
    result = preflight(write_engagement(tmp_path / "e"), environ={})

    assert [(each.name, each.state, each.words) for each in result.items[-3:]] == [
        ("canaries", "not_checked", "version 1 declares no canaries"),
        ("salt", "not_checked", "version 1 declares no salt_env"),
        ("receiver key", "not_checked", "version 1 declares no receiver"),
    ]


def test_open_canaries_are_named_by_id_and_kind_never_by_path_and_the_item_is_ready(tmp_path):
    result = preflight(write_second(tmp_path / "e", canaries=CANARIES), environ={})

    found = item(result, "canaries")

    assert found.state == "ready"
    assert "3 listed, 2 open" in found.words
    assert "c1 (tool_text)" in found.words and "c2 (file)" in found.words
    assert "c3" not in found.words, "a canary the agency confirmed removed is not open"
    assert "/srv/outside" not in found.words and "secret-place" not in found.words


def test_canaries_all_removed_are_ready_with_none_open_and_without_canaries_not_checked(tmp_path):
    removed = [dict(CANARIES[0], removed="2026-11-03")]
    assert item(preflight(write_second(tmp_path / "a", canaries=removed)), "canaries").words == (
        "1 listed, none open"
    )
    none = item(preflight(write_second(tmp_path / "b")), "canaries")
    assert (none.state, none.words) == ("not_checked", "none listed")


def test_the_salt_is_ready_when_its_variable_is_set_and_not_empty_and_the_value_is_never_said(
    tmp_path,
):
    held = write_second(tmp_path / "e")

    ready = item(preflight(held, environ={"DEMO_SALT": SALT_VALUE}), "salt")
    unset = item(preflight(held, environ={}), "salt")
    empty = item(preflight(held, environ={"DEMO_SALT": ""}), "salt")

    assert (ready.state, ready.words) == ("ready", "DEMO_SALT is set")
    assert unset.state == empty.state == "not_ready"
    assert "DEMO_SALT" in unset.words and "DEMO_SALT" in empty.words
    shown = report.render_preflight(preflight(held, environ={"DEMO_SALT": SALT_VALUE}))
    assert SALT_VALUE not in shown


def test_a_salt_shorter_than_32_characters_is_not_ready_and_its_value_is_never_said(tmp_path):
    held = write_second(tmp_path / "e")
    short = SALT_VALUE[:31]

    result = preflight(held, environ={"DEMO_SALT": short})

    assert (item(result, "salt").state, item(result, "salt").words) == (
        "not_ready",
        "DEMO_SALT holds fewer than 32 characters",
    )
    assert short not in report.render_preflight(result)
    assert item(preflight(held, environ={"DEMO_SALT": SALT_VALUE[:32]}), "salt").state == "ready"


def test_a_missing_salt_makes_the_preflight_not_ready(tmp_path):
    result = preflight(write_second(tmp_path / "e"), environ={})

    assert not result.ready and result.exit_code == report.EXIT_NOT_READY
    assert report.render_preflight(result).rstrip().endswith("Not ready: salt.")


def test_the_receiver_key_of_a_reachable_receiver_is_looked_up_like_the_salt(tmp_path):
    held = write_second(tmp_path / "e", receiver=RECEIVER)
    key_value = "key-" + "-".join(["value", "77c1"])

    ready = item(preflight(held, environ={"DEMO_RECEIVER_KEY": key_value}), "receiver key")
    unset = item(preflight(held, environ={}), "receiver key")

    assert (ready.state, ready.words) == ("ready", "DEMO_RECEIVER_KEY is set")
    assert unset.state == "not_ready" and "DEMO_RECEIVER_KEY" in unset.words
    assert key_value not in ready.words


def test_a_local_receiver_or_none_has_no_key_to_check(tmp_path):
    local_held = write_second(tmp_path / "a", receiver={"variant": "local"})
    local = item(preflight(local_held), "receiver key")
    absent = item(preflight(write_second(tmp_path / "b")), "receiver key")

    assert (local.state, absent.state) == ("not_checked", "not_checked")


def test_the_variables_are_read_from_the_environment_of_the_process_by_default(
    tmp_path, monkeypatch
):
    held = write_second(tmp_path / "e")
    monkeypatch.setenv("DEMO_SALT", SALT_VALUE)

    assert item(preflight(held), "salt").state == "ready"
    monkeypatch.delenv("DEMO_SALT")
    assert item(preflight(held), "salt").state == "not_ready"
