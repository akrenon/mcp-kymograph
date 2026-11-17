"""The batch over the corpus: one result per entry and scenario, filed, and the whole compared.

Three layers. The pure parts — the plan, the order, the digest, what may be published — on
their own. The orchestration with a launcher that files made-up recordings into the real
store, so that every failure a run can have is tried without Docker: none of them stops the
batch, each is the state its recording is filed in, and an exit code that says otherwise is a
problem of the fleet. And the corpus itself under runc, end to end: the pair holds over the
stack, two orders make one fleet, and a stack full of failing entries still holds the pair.

Success is read from the store and the recordings, never from what the fleet says it did.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_kymograph import cli, fleet, verdict
from mcp_kymograph.corpus import load as load_manifest
from mcp_kymograph.environment import helper_env
from mcp_kymograph.fleet import REFUSED, UNFILED, FleetError, FleetRun, Launched, Pins, Result
from mcp_kymograph.store import Store
from test_store import finding, recording

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT = FIXTURES / "corpus" / "manifest.yaml"
EXPECTED = json.loads((FIXTURES / "corpus" / "expected.json").read_text())
REFERENCE = FIXTURES / "corpus" / "reference_server.py"
POISON = FIXTURES / "corpus" / "poison_server.py"
DISCOVERY = FIXTURES / "discovery_server.py"
ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"

PINS = Pins("runc", "sha256:" + "5a" * 32, "sha256:" + "7a" * 32)


def write_manifest(tmp_path: Path, *entries: dict) -> Path:
    """A manifest beside the test, its entries in the fixtures. The sandbox delivers an
    entry's files and nothing else, so the command names its server relative to where they
    are delivered (the fixtures directory, their common root), never through ``{dir}``."""

    def rel(path: Path) -> str:
        return os.path.relpath(path, tmp_path)

    listed = []
    for item in entries:
        server = item.get("server", POISON)
        listed.append(
            {
                "name": item["name"],
                "provenance": item.get("provenance", "poison"),
                "source": {"paths": [rel(server), rel(DISCOVERY)]},
                "launch": {
                    "transport": "stdio",
                    "command": item.get("command")
                    or ["{python}", server.relative_to(FIXTURES).as_posix(), *item.get("args", ())],
                },
                "scenarios": [rel(ALL_SIGNALS)],
            }
        )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "entries": listed}))
    return path


def pair(tmp_path: Path) -> Path:
    return write_manifest(
        tmp_path,
        {"name": "reference-server", "provenance": "reference", "server": REFERENCE},
        {"name": "poison-server"},
    )


# -- the pure parts ---------------------------------------------------------------------------


def test_the_plan_is_one_job_per_entry_and_scenario_and_a_real_world_entry_is_refused(tmp_path):
    path = write_manifest(
        tmp_path,
        {"name": "reference-server", "provenance": "reference", "server": REFERENCE},
        {"name": "outside", "provenance": "real-world"},
    )
    jobs = fleet.plan(load_manifest(path))
    assert [(j.index, j.entry, j.scenario, j.provenance) for j in jobs] == [
        (0, "reference-server", "all-signals", "reference"),
        (1, "outside", "all-signals", "real-world"),
    ]
    assert jobs[0].refusal is None
    assert "only under runsc, not runc" in jobs[1].refusal
    assert "not run under a weaker isolation" in jobs[1].refusal


def test_an_order_must_name_every_job_exactly_once(tmp_path):
    with Store.open(tmp_path / "s.sqlite") as store, pytest.raises(FleetError, match="every"):
        fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS,
                  order=[("poison-server", "all-signals")], launcher=_never)  # fmt: skip


def test_an_order_that_names_every_job_once_is_the_order_they_run_in(tmp_path):
    jobs = fleet.plan(load_manifest(pair(tmp_path)))
    keys = [job.key for job in jobs]
    assert len(keys) == 2
    # As given on the command line or read from JSON: lists as well as tuples.
    order = [list(key) for key in reversed(keys)]
    assert [job.key for job in fleet._ordered(jobs, order)] == list(reversed(keys))
    for wrong in (
        [*keys, keys[0]],
        [keys[0], keys[0]],
        [*keys, ("x", "y")],
        [(*keys[0], "z"), keys[1]],
    ):
        with pytest.raises(FleetError, match="every"):
            fleet._ordered(jobs, wrong)


def test_the_fleet_runs_under_runc_whatever_is_handed_in(tmp_path):
    """The floor is not a parameter: host pins are refused before anything starts."""
    with Store.open(tmp_path / "s.sqlite") as store, pytest.raises(FleetError, match="runc"):
        fleet.run(pair(tmp_path), store, tmp_path / "runs",
                  pins=Pins("host", "a", "b"), launcher=_never)  # fmt: skip
    assert not (tmp_path / "runs").exists()


def test_a_fleet_over_an_empty_corpus_is_refused_not_reported_complete(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"version": 1, "entries": []}))
    with Store.open(tmp_path / "s.sqlite") as store:
        with pytest.raises(FleetError, match="no entries"):
            fleet.run(empty, store, tmp_path / "runs", pins=PINS, launcher=_never)
        assert store.fleets() == []
    assert not (tmp_path / "runs").exists()


def _never(*_args, **_kwargs):
    raise AssertionError("nothing may be launched")


def _fleet_run(results, processed, *, fleet_id="f1", started="t0", parallel=1) -> FleetRun:
    return FleetRun(
        fleet=fleet_id,
        started_utc=started,
        finished_utc=started,
        manifest={"source": "m", "digest": "sha256:" + "33" * 32},
        tool={"version": "0", "content": "sha256:" + "11" * 32},
        pins=PINS,
        parallel=parallel,
        processed=processed,
        results={r.key: r for r in results},
    )


def _result(entry, state=verdict.COMPLETE, findings=(), run="r", provenance="poison"):
    return Result(entry, "scn", provenance, state, exit_code=0, run=run + entry,
                  findings=tuple(sorted(findings)), context={"server_version": "v"})  # fmt: skip


def test_the_digest_is_independent_of_order_run_ids_time_and_parallelism():
    a = [_result("a", findings=['["k1"]']), _result("b")]
    b = [_result("b", run="other"), _result("a", findings=['["k1"]'], run="other")]
    first = _fleet_run(a, [("a", "scn"), ("b", "scn")])
    second = _fleet_run(b, [("b", "scn"), ("a", "scn")], fleet_id="f2", started="t9", parallel=4)
    assert first.digest == second.digest


@pytest.mark.parametrize(
    "change",
    [
        {"findings": ('["k1"]', '["k2"]')},
        {"state": verdict.INCOMPLETE},
        {"provenance": "reference"},
    ],
)
def test_the_digest_moves_with_what_was_found(change):
    """The other direction of the instrument: a digest that did not move here would also
    call two different fleets the same."""
    base = _fleet_run([_result("a", findings=['["k1"]'])], [("a", "scn")])
    moved = _result("a", findings=['["k1"]'])
    for name, value in change.items():
        setattr(moved, name, value)
    assert _fleet_run([moved], [("a", "scn")]).digest != base.digest


def test_two_fleets_incomplete_for_different_reasons_do_not_have_the_same_digest():
    """The state alone would make them one result; the causes tell them apart. The
    same causes give the same digest, so a cause carries no run id, time or order."""
    lossy = _result("a", state=verdict.INCOMPLETE)
    lossy.causes = ("udp_loss",)
    unanswered = _result("a", state=verdict.INCOMPLETE, run="other")
    unanswered.causes = ("step_unanswered",)
    again = _result("a", state=verdict.INCOMPLETE, run="third")
    again.causes = ("udp_loss",)
    first, second, third = (_fleet_run([r], [("a", "scn")]) for r in (lossy, unanswered, again))
    assert first.digest != second.digest
    assert first.digest == third.digest


def test_real_world_findings_never_reach_what_may_be_published():
    record = _fleet_run(
        [
            _result("ours", findings=['["s","v","t","scn","st","loc","sig"]']),
            _result("theirs", findings=['["x","v","t","scn","st","loc","sig"]'],
                    provenance="real-world"),
        ],
        [("ours", "scn"), ("theirs", "scn")],
    )  # fmt: skip
    output = record.to_dict()
    published = json.dumps(output["findings"])
    assert '"x"' not in published and "theirs" not in published
    assert [f["entry"] for f in output["findings"]["poison"]] == ["ours"]
    assert output["disclosure_candidates"]["real-world"] == 1
    assert "store findings --provenance real-world" in output["disclosure_candidates"]["note"]


# -- the orchestration, with made-up recordings in the real store -----------------------------


CONSISTENT = {
    "seq": 60,
    "type": "egress_summary",
    "consistent": True,
    "udp_loss": {"kernel": 0, "sink": 0, "lost": 0, "unseen_destinations": 0, "rate": 0.0},
}


def made_up(job, pins, out_dir: Path, *, findings=(), extra=(), environment=None, code=0):
    """File what a run of this job would have recorded into its run directory."""
    out_dir.mkdir(parents=True)
    env = environment or pins.to_dict()
    path = recording(
        out_dir,
        list(findings),
        name="events",
        entry=job.entry,
        provenance=job.provenance,
        isolation=env["isolation"],
        sandbox_image=env["sandbox_image"],
        target_image=env["target_image"],
        extra=[CONSISTENT, *extra],
    )
    (out_dir / "run").mkdir()
    path.rename(out_dir / "run" / "events.jsonl")
    return Launched(code, out_dir / "run" / "events.jsonl")


def launcher(plan: dict):
    """A launcher that does, per entry, what ``plan`` says; and remembers what it launched."""
    launched = []

    def launch(job, pins, manifest_path, out_dir, *, step_timeout, job_timeout,
               client_settle_timeout, processes):  # fmt: skip
        launched.append(job.entry)
        action = plan[job.entry]
        if action == "raise":
            raise RuntimeError("the launcher itself failed")
        if action == "refused":
            return Launched(2, None, stderr="kymograph: the entry's files cannot be delivered\n")
        return made_up(job, pins, out_dir, **action)

    launch.launched = launched
    return launch


def five(tmp_path: Path) -> Path:
    return write_manifest(
        tmp_path,
        {"name": "reference-server", "provenance": "reference", "server": REFERENCE},
        {"name": "poison-server"},
        {"name": "broken-sandbox"},
        {"name": "silent"},
        {"name": "crashing-launcher"},
        {"name": "undeliverable"},
        {"name": "outside", "provenance": "real-world"},
    )


def test_a_failed_entry_is_a_recorded_result_and_the_batch_goes_on(tmp_path):
    """Every way one run can fail, in one batch: each is filed in its state, with its reason,
    and every other entry is still run and is still complete. The real-world entry is refused
    without being launched at all."""
    plan = launcher(
        {
            "reference-server": {},
            "poison-server": {"findings": [finding(5, server="poison-server")]},
            "broken-sandbox": {"extra": [{"type": "sandbox_failed", "condition": "probe",
                                          "phase": "before_target"}], "code": 5},
            "silent": {"extra": [{"type": "server_failed", "reason": "no_answer"}], "code": 4},
            "crashing-launcher": "raise",
            "undeliverable": "refused",
        }
    )  # fmt: skip
    with Store.open(tmp_path / "store.sqlite") as store:
        record = fleet.run(five(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=plan)
        filed = store.fleet(record.fleet)
    states = {entry: r["state"] for (entry, _), r in filed["results"].items()}
    assert states == {
        "reference-server": verdict.COMPLETE,
        "poison-server": verdict.COMPLETE,
        "broken-sandbox": verdict.SANDBOX_FAILED,
        "silent": verdict.SERVER_FAILED,
        "crashing-launcher": UNFILED,
        "undeliverable": REFUSED,
        "outside": REFUSED,
    }
    assert "outside" not in plan.launched and len(plan.launched) == 6
    reasons = {entry: r["problems"] for (entry, _), r in filed["results"].items()}
    assert any("only under runsc" in p for p in reasons["outside"])
    assert any("cannot be delivered" in p for p in reasons["undeliverable"])
    assert any("the launcher itself failed" in p for p in reasons["crashing-launcher"])
    assert record.problems == [], "every exit code agreed with its recording"
    assert record.state == verdict.SANDBOX_FAILED and not record.complete
    with Store.open(tmp_path / "store.sqlite") as store:
        assert len(store.runs()) == 4  # the four that made a recording, all filed


def test_an_exit_code_that_contradicts_the_recording_is_a_problem_of_the_fleet(tmp_path):
    """The run says 0, its recording is filed server_failed: the fleet goes by the recording
    and writes the contradiction down."""
    plan = launcher({"reference-server": {}, "poison-server": {
        "extra": [{"type": "server_failed", "reason": "no_answer"}], "code": 0}})  # fmt: skip
    with Store.open(tmp_path / "store.sqlite") as store:
        record = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=plan)
    assert record.results[("poison-server", "all-signals")].state == verdict.SERVER_FAILED
    assert any(
        "poison-server/all-signals: exit code 0, but its recording is filed server_failed (4)" in p
        for p in record.problems
    ), record.problems


def test_a_run_under_another_environment_than_the_fleet_s_is_a_problem(tmp_path):
    other = {**PINS.to_dict(), "sandbox_image": "sha256:" + "5b" * 32}
    plan = launcher({"reference-server": {}, "poison-server": {"environment": other}})
    with Store.open(tmp_path / "store.sqlite") as store:
        record = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=plan)
    assert record.results[("poison-server", "all-signals")].state == verdict.COMPLETE
    assert any("poison-server/all-signals observed under" in p for p in record.problems)
    assert not record.complete


def test_each_fleet_is_compared_with_the_one_before(tmp_path):
    """The second fleet against the first through the store: one entry gained a finding,
    nothing else moved — named entry by entry, with the run comparison's axes."""
    manifest = pair(tmp_path)
    with Store.open(tmp_path / "store.sqlite") as store:
        first = fleet.run(
            manifest,
            store,
            tmp_path / "runs",
            pins=PINS,
            launcher=launcher({"reference-server": {}, "poison-server": {}}),
        )
        second = fleet.run(manifest, store, tmp_path / "runs", pins=PINS, launcher=launcher(
            {"reference-server": {}, "poison-server": {
                "findings": [finding(5, server="poison-server")]}}))  # fmt: skip
        assert fleet.previous(store, first.fleet) is None
        assert fleet.previous(store, second.fleet) == first.fleet
        compared = fleet.compare(store, first.fleet, second.fleet)
    assert compared["complete"] and not compared["same_result"]
    by_entry = {e["entry"]: e for e in compared["entries"]}
    assert by_entry["reference-server"]["new"] == [] and by_entry["reference-server"]["gone"] == []
    assert [n["identity"]["signal"] for n in by_entry["poison-server"]["new"]] == ["hidden_comment"]
    assert set(by_entry["poison-server"]["axes"]) == {"server", "tool", "scenario", "environment"}
    assert not any(axis["moved"] for axis in compared["axes"].values())


# -- the corpus under runc, end to end ----------------------------------------------------------


def _image(reference: str) -> str | None:
    if shutil.which("docker") is None:
        return None
    done = subprocess.run(  # noqa: S603
        ["docker", "image", "inspect", "--format", "{{.Id}}", reference],  # noqa: S607
        capture_output=True, env=helper_env(), check=False,
    )  # fmt: skip
    return done.stdout.decode().strip() if done.returncode == 0 else None


docker = pytest.mark.docker


def fleet_cli(tmp_path: Path, manifest: Path, *extra: str) -> tuple[int, dict]:
    store = tmp_path / "store.sqlite"
    out = tmp_path / "out.json"
    with out.open("w") as handle:
        done = subprocess.run(  # noqa: S603
            [os.sys.executable, "-m", "mcp_kymograph.cli", "fleet", "run", "-q", "--manifest",
             str(manifest), "--store", str(store), "--out-dir", str(tmp_path / "runs"), *extra],
            stdout=handle, stderr=subprocess.PIPE, timeout=600, check=False,
        )  # fmt: skip
    return done.returncode, json.loads(out.read_text())


def projected(store: Store, run: str) -> list[dict]:
    return sorted(
        ({n: key[n] for n in ("statement", "locator", "signal")}
         for key, _ in store.findings_of(run).values()),
        key=json.dumps,
    )  # fmt: skip


@docker
def test_the_pair_holds_over_the_stack(tmp_path):
    """Reference 0, poison 4, at the pinned places, both complete — read from the store the
    fleet filed into, and every run under the one sandbox the fleet pinned."""
    code, output = fleet_cli(tmp_path, PROJECT)
    assert code == 0, output["fleet"]["problems"]
    record = output["fleet"]
    assert record["state"] == verdict.COMPLETE and record["problems"] == []
    with Store.open(tmp_path / "store.sqlite") as store:
        filed = store.fleet(record["fleet"])
        assert filed["digest"] == record["digest"]
        for name in ("reference", "poison"):
            expected = EXPECTED["entries"][name]
            result = filed["results"][(expected["server"], EXPECTED["scenario"])]
            assert (result["state"], result["exit_code"]) == (verdict.COMPLETE, 0)
            info = store.run_info(result["run"])
            assert info.complete and info.provenance == name
            assert (info.isolation, info.sandbox_image, info.target_image) == (
                "runc", filed["sandbox_image"], filed["target_image"])  # fmt: skip
            assert projected(store, result["run"]) == sorted(expected["findings"], key=json.dumps)
    assert {k: len(v) for k, v in record["findings"].items()} == {"reference": 0, "poison": 4}


@docker
def test_two_orders_make_one_and_the_same_fleet(tmp_path):
    """Forward, then reversed, one run at a time so the order they are processed in is
    certain to differ — and a third two at a time. The result does not differ: the same
    digest, and each fleet's comparison with the one before finds nothing new, nothing gone,
    nothing moved."""
    jobs = [job.key for job in fleet.plan(load_manifest(PROJECT))]
    pins = fleet.pin()
    with Store.open(tmp_path / "store.sqlite") as store:
        runs = [
            fleet.run(PROJECT, store, tmp_path / "runs", pins=pins, parallel=1, order=jobs),
            fleet.run(PROJECT, store, tmp_path / "runs", pins=pins, parallel=1,
                      order=list(reversed(jobs))),
            fleet.run(PROJECT, store, tmp_path / "runs", pins=pins, parallel=2),
        ]  # fmt: skip
        compared = [
            fleet.compare(store, a.fleet, b.fleet) for a, b in zip(runs, runs[1:], strict=False)
        ]
        digests = {info["digest"] for info in store.fleets()}
    assert runs[0].processed == jobs
    assert runs[1].processed == list(reversed(jobs)) != runs[0].processed
    assert all(r.complete for r in runs), [r.problems for r in runs]
    assert len({r.digest for r in runs}) == 1 and digests == {runs[0].digest}
    for comparison in compared:
        assert comparison["complete"] and comparison["same_result"]
        for item in comparison["entries"]:
            assert (item["change"], item["new"], item["gone"], item["moved_axes"]) == (
                "compared",
                [],
                [],
                [],
            )


@docker
def test_a_stack_of_failing_entries_records_each_and_still_holds_the_pair(tmp_path):
    """The pair beside a server that never answers, one that dies after its handshake, a
    real-world entry, and one whose sandbox cannot be built: each is the state its recording
    says, the exit code agrees with it, nothing stops the batch, and the pair is still 0 and
    4, complete."""
    manifest = write_manifest(
        tmp_path,
        {"name": "reference-server", "provenance": "reference", "server": REFERENCE},
        {"name": "poison-server"},
        {"name": "silent", "args": ["--silent"]},
        {"name": "dying", "args": ["--exit-after", "0"]},
        {"name": "outside", "provenance": "real-world"},
        {"name": "no-sandbox"},
    )
    pins = fleet.pin()

    def one_broken(job, pins_, *args, **kwargs):
        if job.entry == "no-sandbox":
            pins_ = Pins(pins_.isolation, pins_.sandbox_image, "mcp-kymograph-no-such-image:0")
        return fleet.launch(job, pins_, *args, **kwargs)

    with Store.open(tmp_path / "store.sqlite") as store:
        record = fleet.run(manifest, store, tmp_path / "runs", pins=pins, parallel=3,
                           step_timeout=2.0, launcher=one_broken)  # fmt: skip
        filed = store.fleet(record.fleet)
        states = {e: (r["state"], r["exit_code"]) for (e, _), r in filed["results"].items()}
        assert states == {
            "reference-server": (verdict.COMPLETE, 0),
            "poison-server": (verdict.COMPLETE, 0),
            "silent": (verdict.SERVER_FAILED, 4),
            "dying": (verdict.INCOMPLETE, 3),
            "outside": (REFUSED, None),
            "no-sandbox": (verdict.SANDBOX_FAILED, 5),
        }
        poison = filed["results"][("poison-server", "all-signals")]
        assert len(projected(store, poison["run"])) == 4
        reference = filed["results"][("reference-server", "all-signals")]
        assert projected(store, reference["run"]) == []
    # The one thing the fleet itself must say: the broken entry did not observe under its pins.
    assert [p for p in record.problems if "no-sandbox" in p], record.problems
    assert all("no-sandbox" in p for p in record.problems), record.problems
    assert record.state == verdict.SANDBOX_FAILED
    assert verdict.EXIT_CODES[record.state] == cli.EXIT_SANDBOX_FAILED


def test_the_command_line_compares_the_last_two_fleets_and_lists_them(tmp_path, capsys):
    manifest = pair(tmp_path)
    database = tmp_path / "store.sqlite"
    with Store.open(database) as store:
        for _ in range(2):
            fleet.run(manifest, store, tmp_path / "runs", pins=PINS,
                      launcher=launcher({"reference-server": {}, "poison-server": {}}))  # fmt: skip
    capsys.readouterr()
    assert cli.main(["fleet", "diff", "-q", "--store", str(database)]) == 0
    compared = json.loads(capsys.readouterr().out)
    assert compared["complete"] and compared["same_result"]
    assert cli.main(["fleet", "runs", "--store", str(database)]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert [f["fleet"] for f in listed] == [compared["before"], compared["after"]]
    assert all("results" not in f for f in listed)
    assert cli.main(["fleet", "diff", "--store", str(database), compared["before"]]) == 2


def test_real_world_findings_are_queried_apart_on_the_command_line(tmp_path, capsys):
    path = recording(tmp_path, [finding(5)], provenance="real-world")
    database = str(tmp_path / "store.sqlite")
    assert cli.main(["store", "ingest", "-q", "--store", database, str(path)]) == 0
    capsys.readouterr()
    assert cli.main(["store", "findings", "--store", database, "--provenance", "real-world"]) == 0
    (found,) = json.loads(capsys.readouterr().out)
    assert found["signal"] == "hidden_comment"
    assert cli.main(["store", "findings", "--store", database, "--provenance", "poison"]) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_every_run_is_handed_the_fleet_s_wait_for_the_script_s_end(tmp_path, monkeypatch):
    """The wait is a property of the batch, chosen once: each run's drive gets it."""
    seen = []

    class Done:
        pid = -1
        returncode = 0

        def communicate(self, timeout=None):
            return b"", b""

    def popen(argv, **_kwargs):
        seen.append(argv)
        return Done()

    monkeypatch.setattr(fleet.subprocess, "Popen", popen)
    job = fleet.plan(load_manifest(PROJECT))[0]
    fleet.launch(job, Pins("runc", "a", "b"), PROJECT, tmp_path / "out", step_timeout=2.0,
                 job_timeout=9.0, client_settle_timeout=12.5)  # fmt: skip
    (argv,) = seen
    assert argv[argv.index("--client-settle-timeout") + 1] == "12.5"


def test_why_a_run_is_incomplete_is_kept_per_result_compared_and_said_in_the_report(
    tmp_path, capsys
):
    """Two incomplete results, for two reasons: the fleet keeps each one's cause, its
    comparison carries them on both sides, and the report says them beside the state."""
    lossy = {
        "type": "egress_summary",
        "consistent": True,
        "udp_loss": {"kernel": 9, "sink": 8, "lost": 1, "unseen_destinations": 0},
    }
    unanswered = {
        "type": "step_unanswered",
        "step": "tools/list",
        "pages": 0,
        "reason": "no_answer",
    }
    plan = {
        "reference-server": {"extra": [lossy], "code": 3},
        "poison-server": {"extra": [unanswered], "code": 3},
    }
    with Store.open(tmp_path / "store.sqlite") as store:
        first = fleet.run(
            pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launcher(plan)
        )
        second = fleet.run(
            pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=launcher(plan)
        )
        filed = store.fleet(second.fleet)
        compared = fleet.compare(store, first.fleet, second.fleet)
    causes = {entry: r["causes"] for (entry, _), r in filed["results"].items()}
    assert causes == {"reference-server": ["udp_loss"], "poison-server": ["step_unanswered"]}
    assert first.problems == [] and second.problems == []
    by_entry = {e["entry"]: e for e in compared["entries"]}
    assert by_entry["reference-server"]["causes"] == {"before": ["udp_loss"], "after": ["udp_loss"]}
    output = {r["entry"]: r for r in second.to_dict()["results"]}
    assert output["reference-server"]["causes"] == ["udp_loss"]
    cli._report_fleet(cli.TerminalView(sys.stderr), second, None)
    said = capsys.readouterr().err
    assert "reference-server/all-signals: incomplete [udp_loss]" in said
    assert "poison-server/all-signals: incomplete [step_unanswered]" in said


@docker
def test_servers_that_never_start_are_server_failed_in_the_fleet_without_a_contradiction(tmp_path):
    """Under runc the command runs in the container: one that is not there, a script that is
    not there, one that ends at once. Each run exits 4, its recording is filed server_failed,
    and the fleet finds nothing to contradict between the two."""
    manifest = write_manifest(
        tmp_path,
        {"name": "missing-binary", "command": ["/nonexistent/server"]},
        {"name": "missing-script", "command": ["{python}", "corpus/not-there.py"]},
        {"name": "ends-at-once", "command": ["{python}", "-c", "import sys; sys.exit(3)"]},
    )
    code, output = fleet_cli(tmp_path, manifest)
    assert code == verdict.EXIT_SERVER_FAILED
    assert output["fleet"]["problems"] == []
    results = {r["entry"]: r for r in output["fleet"]["results"]}
    for entry in ("missing-binary", "missing-script", "ends-at-once"):
        assert (results[entry]["state"], results[entry]["exit_code"]) == ("server_failed", 4)
        assert "server_silent" in results[entry]["causes"], results[entry]
