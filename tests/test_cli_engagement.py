"""The command line under an engagement file: ``--engagement`` on ``drive``, ``run`` and
``store ingest``, ``engagement show``, and the refusal record.

Every refusal here is checked the way the gate's other refusals are: exit 2, the words on stderr
naming the file and the condition, no process started and no run directory left behind. Under a
file a refusal is also written down — one line in ``refusals.jsonl`` beside the run directories,
read back here through :func:`engagement.read_refusals` — and a run that is not refused records
the file's id, digest and window, and nothing else of it.
"""

import asyncio
import contextlib
import json
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
TOY = str(FIXTURES / "toy_server.py")
DISCOVERY = str(FIXTURES / "discovery_server.py")
SCENARIO = FIXTURES / "scenarios" / "all-signals.yaml"
OTHER_SCENARIO = FIXTURES / "scenarios" / "instruction-in-disguise.yaml"
MANIFEST = FIXTURES / "corpus" / "manifest.yaml"

#: Values of the file that must never reach a recording or a refusal record.
NEVER_RECORDED = ("CUSTOMER-CANARY-4711", "REFERENCE-CANARY-4712", "CONTACT-CANARY-4713")


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_engagement(directory: Path, name: str = "engagement.json", **changes) -> Path:
    """An engagement file in ``directory`` whose window holds now, covering the local child and
    the fixtures' ``all-signals`` scenario (copied beside it), as JSON; ``changes`` replace
    top-level keys, and a value of None removes one."""
    directory.mkdir(parents=True, exist_ok=True)
    listed = directory / "all-signals.yaml"
    shutil.copyfile(SCENARIO, listed)
    now = datetime.now(timezone.utc)
    data = {
        "version": 1,
        "id": "acme-2026-10",
        "customer": NEVER_RECORDED[0],
        "reference": NEVER_RECORDED[1],
        "contacts": [{"name": NEVER_RECORDED[2], "role": "security lead", "reach": "phone"}],
        "window": {"from": utc(now - timedelta(days=1)), "until": utc(now + timedelta(days=1))},
        "targets": [{"host": "127.0.0.1"}],
        "scenarios": [
            {"path": "all-signals.yaml", "sha256": sha256(listed.read_bytes()).hexdigest()}
        ],
        "actions": {"list": True, "call": False},
        "redaction": {"mask_keys": ["customer_id"], "mask_patterns": []},
    }
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    path = directory / name
    path.write_text(json.dumps(data, indent=2))
    return path


@pytest.fixture
def nothing_starts(monkeypatch):
    """Fails the test if a server process is started, over stdio or through the sandbox."""
    started = []

    async def must_not_run(*args, **kwargs):
        started.append(args)
        raise AssertionError("a process was started although the run was refused")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", must_not_run)
    return started


def refusals_in(out_dir: Path) -> list[engagement.RefusalRecord]:
    return engagement.read_refusals(out_dir / engagement.REFUSALS_FILE)


def run_directories(out_dir: Path) -> list[Path]:
    if not out_dir.exists():
        return []
    # not the slots of pacing (mcp_kymograph.pacing), which are a directory of the out-dir too
    return [path for path in out_dir.iterdir() if path.is_dir() and path.name != ".pacing"]


def recording_in(out_dir: Path) -> Path:
    (run,) = run_directories(out_dir)
    return run / "events.jsonl"


def events_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def started_of(path: Path) -> dict:
    return next(event for event in events_of(path) if event["type"] == "run_started")


# -- a run under a file ----------------------------------------------------------------------


def test_a_drive_under_a_file_records_its_id_digest_and_window_and_nothing_else(tmp_path):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"
    loaded = engagement.load(held)

    code = cli.main(
        [
            "drive",
            "-q",
            "--engagement",
            str(held),
            "--scenario",
            str(held.parent / "all-signals.yaml"),
            "--out-dir",
            str(out_dir),
            "--",
            sys.executable,
            DISCOVERY,
        ]
    )

    assert code == 0
    recording = recording_in(out_dir)
    authorization = started_of(recording)["authorization"]
    assert authorization["engagement"] == {
        "engagement_id_declared": "acme-2026-10",
        "engagement_digest": loaded.digest,
        "window_declared": loaded.window_declared(),
    }
    assert authorization["engagement_confirmed_flag"] is False, "recorded as typed"
    raw = recording.read_bytes()
    for value in (*NEVER_RECORDED, b"security lead", b"customer_id"):
        token = value if isinstance(value, bytes) else value.encode()
        assert token not in raw
    finished = next(e for e in events_of(recording) if e["type"] == "run_finished")
    assert finished["window_exceeded"] is False
    assert not (out_dir / engagement.REFUSALS_FILE).exists(), "nothing was refused"


def test_the_file_s_mask_keys_join_the_command_line_s(tmp_path, monkeypatch):
    held = write_engagement(tmp_path / "engagement")
    seen = []
    real = cli.Masker

    def recording_masker(*, extra_keys):
        seen.append(list(extra_keys))
        return real(extra_keys=extra_keys)

    monkeypatch.setattr(cli, "Masker", recording_masker)
    code = cli.main(
        [
            "drive",
            "-q",
            "--engagement",
            str(held),
            "--mask-key",
            "tenant",
            "--out-dir",
            str(tmp_path / "runs"),
            "--",
            sys.executable,
            DISCOVERY,
        ]
    )

    assert code == 0
    assert seen == [["tenant", "customer_id"]]


def test_a_run_without_a_file_records_none(tmp_path):
    out_dir = tmp_path / "runs"
    assert (
        cli.main(["drive", "-q", "--out-dir", str(out_dir), "--", sys.executable, DISCOVERY]) == 0
    )
    assert started_of(recording_in(out_dir))["authorization"]["engagement"] is None


# -- the gate's conditions, each through the command line ---------------------------------


def _future_window():
    now = datetime.now(timezone.utc)
    return {"from": utc(now + timedelta(days=1)), "until": utc(now + timedelta(days=2))}


def _past_window():
    now = datetime.now(timezone.utc)
    return {"from": utc(now - timedelta(days=2)), "until": utc(now - timedelta(days=1))}


CONDITION_CASES = {
    "draft": ({"customer": "[CUSTOMER NAME]"}, []),
    "before_window": ({"window": _future_window()}, []),
    "after_window": ({"window": _past_window()}, []),
    "target_not_listed": (
        {"targets": [{"host": "mcp.example-customer.test", "paths": ["/mcp"]}]},
        [],
    ),
    "port_not_listed": (
        {"targets": [{"host": "127.0.0.1", "ports": [8443]}]},
        ["--target", "127.0.0.1:9000"],
    ),
    "builtin_scenario": ({}, ["--scenario", "tool-poisoning"]),
    "scenario_not_listed": ({}, ["--scenario", str(OTHER_SCENARIO)]),
    "lists_not_permitted": ({"actions": {"list": False, "call": False}}, []),
}


@pytest.mark.parametrize("condition", sorted(CONDITION_CASES))
def test_each_condition_refuses_before_anything_starts_and_is_written_down(
    condition, tmp_path, nothing_starts, capsys
):
    changes, extra = CONDITION_CASES[condition]
    held = write_engagement(tmp_path / "engagement", **changes)
    out_dir = tmp_path / "runs"

    code = cli.main(
        [
            "drive",
            "--engagement",
            str(held),
            *extra,
            "--out-dir",
            str(out_dir),
            "--",
            sys.executable,
            DISCOVERY,
        ]
    )

    assert code == cli.EXIT_REFUSED == 2
    assert nothing_starts == []
    assert run_directories(out_dir) == [], "a refused run leaves no run directory"
    said = capsys.readouterr().err
    assert f"{held}: {condition}: " in said
    (record,) = refusals_in(out_dir)
    assert record.reason == condition
    assert record.exit_code == 2
    assert record.engagement_digest == engagement.load(held).digest
    assert record.engagement_id_declared == "acme-2026-10"
    assert f"{condition}: " in record.message
    assert "drive" in record.command and DISCOVERY in record.command
    assert (out_dir / engagement.REFUSALS_FILE).stat().st_mode & 0o777 == 0o600
    assert out_dir.stat().st_mode & 0o777 == 0o700
    for value in NEVER_RECORDED:
        assert value not in (out_dir / engagement.REFUSALS_FILE).read_text()


def test_below_isolation_refuses_a_corpus_run_under_a_weaker_isolation(
    tmp_path, nothing_starts, capsys
):
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "127.0.0.1", "isolation": "runc"}]
    )
    out_dir = tmp_path / "runs"

    code = cli.main(
        [
            "drive",
            "--engagement",
            str(held),
            "--manifest",
            str(MANIFEST),
            "--entry",
            "reference-server",
            "--isolation",
            "host",
            "--out-dir",
            str(out_dir),
        ]
    )

    assert code == 2
    assert nothing_starts == []
    assert f"{held}: below_isolation: " in capsys.readouterr().err
    assert [record.reason for record in refusals_in(out_dir)] == ["below_isolation"]


def test_path_not_listed_refuses_an_http_run_before_anything_connects(
    tmp_path, monkeypatch, capsys
):
    def must_not_connect(*args, **kwargs):
        raise AssertionError("nothing may connect when the file refuses the run")

    monkeypatch.setattr("socket.create_connection", must_not_connect)
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "127.0.0.1", "ports": [9], "paths": ["/mcp"]}]
    )
    out_dir = tmp_path / "runs"

    code = cli.main(
        [
            "drive",
            "--engagement",
            str(held),
            "--http",
            "http://127.0.0.1:9/other",
            "--out-dir",
            str(out_dir),
        ]
    )

    assert code == 2
    assert f"{held}: path_not_listed: " in capsys.readouterr().err
    assert [record.reason for record in refusals_in(out_dir)] == ["path_not_listed"]


def test_calls_not_permitted_refuses_a_script_that_calls(tmp_path, nothing_starts, capsys):
    held = write_engagement(tmp_path / "engagement")
    script = tmp_path / "calls.json"
    script.write_text(
        json.dumps(
            {
                "version": 1,
                "name": "calls-one",
                "steps": [
                    "initialize",
                    {"list": "tools/list"},
                    {"call": {"tool": "echo", "arguments": {}}},
                ],
            }
        )
    )
    out_dir = tmp_path / "runs"

    code = cli.main(
        [
            "drive",
            "--engagement",
            str(held),
            "--script",
            str(script),
            "--out-dir",
            str(out_dir),
            "--",
            sys.executable,
            DISCOVERY,
        ]
    )

    assert code == 2
    assert nothing_starts == []
    assert f"{held}: calls_not_permitted: " in capsys.readouterr().err
    assert [record.reason for record in refusals_in(out_dir)] == ["calls_not_permitted"]


def test_the_file_does_not_imply_the_confirmation(tmp_path, nothing_starts, capsys):
    """A non-local target with a scenario needs --engagement-confirmed with a file as without
    one: the file narrows the gate, and never opens it. The refusal is today's gate's, and it is
    written down like the file's own."""
    held = write_engagement(
        tmp_path / "engagement", targets=[{"host": "mcp.example.test", "paths": ["/mcp"]}]
    )
    out_dir = tmp_path / "runs"

    code = cli.main(
        [
            "run",
            "--engagement",
            str(held),
            "--target",
            "mcp.example.test",
            "--scenario",
            str(held.parent / "all-signals.yaml"),
            "--out-dir",
            str(out_dir),
            "--",
            sys.executable,
            TOY,
        ]
    )

    assert code == 2
    assert nothing_starts == []
    assert "--engagement-confirmed" in capsys.readouterr().err
    assert [record.reason for record in refusals_in(out_dir)] == ["not_confirmed"]


def test_a_refusal_after_the_file_is_read_is_written_down_with_its_own_reason(
    tmp_path, nothing_starts
):
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--scenario", str(tmp_path / "missing.yaml"),
         "--out-dir", str(out_dir), "--", sys.executable, DISCOVERY]
    )  # fmt: skip

    assert code == 2
    assert [record.reason for record in refusals_in(out_dir)] == ["scenario"]


def test_refusals_are_appended_one_line_each(tmp_path, nothing_starts):
    held = write_engagement(tmp_path / "engagement", actions={"list": False, "call": False})
    out_dir = tmp_path / "runs"
    argv = ["drive", "--engagement", str(held), "--out-dir", str(out_dir), "--", sys.executable]

    assert cli.main([*argv, DISCOVERY]) == 2
    assert cli.main([*argv, DISCOVERY, "--token=s3cr3t-value"]) == 2

    first, second = refusals_in(out_dir)
    assert first.reason == second.reason == "lists_not_permitted"
    assert "s3cr3t-value" not in (out_dir / engagement.REFUSALS_FILE).read_text(), "masked"


def test_a_file_that_is_refused_gates_nothing_and_records_nothing(tmp_path, nothing_starts, capsys):
    held = write_engagement(tmp_path / "engagement", unknown_key="x")
    out_dir = tmp_path / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--out-dir", str(out_dir), "--", sys.executable,
         DISCOVERY]
    )  # fmt: skip

    assert code == 2
    assert str(held.name) in capsys.readouterr().err
    assert not out_dir.exists(), "a refusal before the file is read is not recorded"


def test_a_refusal_that_cannot_be_written_down_says_so_and_still_refuses(
    tmp_path, nothing_starts, capsys
):
    git = shutil.which("git")
    assert git, "this test needs a git binary"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=repo, check=True)  # noqa: S603
    held = write_engagement(tmp_path / "engagement", actions={"list": False, "call": False})
    out_dir = repo / "runs"

    code = cli.main(
        ["drive", "--engagement", str(held), "--out-dir", str(out_dir), "--", sys.executable,
         DISCOVERY]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert "lists_not_permitted" in said
    assert f"the refusal is not written to {engagement.REFUSALS_FILE}" in said
    assert not out_dir.exists()


# -- store ingest --engagement --------------------------------------------------------------


def _drive_under(held: Path, out_dir: Path) -> Path:
    code = cli.main(
        ["drive", "-q", "--engagement", str(held), "--manifest", str(MANIFEST), "--entry",
         "reference-server", "--isolation", "host", "--out-dir", str(out_dir)]
    )  # fmt: skip
    assert code == 0
    (run,) = sorted(run_directories(out_dir))[-1:]
    return run / "events.jsonl"


def test_store_ingest_under_a_file_makes_the_store_the_engagement_s(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement")
    recording = _drive_under(held, tmp_path / "runs")
    database = tmp_path / "findings.sqlite"

    code = cli.main(
        ["store", "ingest", "-q", "--store", str(database), "--engagement", str(held),
         str(recording)]
    )  # fmt: skip

    assert code == 0
    capsys.readouterr()
    with Store.open_read_only(database) as store:
        assert store.engagement()["engagement_digest"] == engagement.load(held).digest
        (run,) = store.runs()
    assert run.engagement_id_declared == "acme-2026-10"
    assert run.engagement_digest == engagement.load(held).digest
    with contextlib.closing(sqlite3.connect(database)) as connection:
        (chain,) = connection.execute(
            "SELECT value FROM meta WHERE name = 'engagement_chain'"
        ).fetchone()
    assert NEVER_RECORDED[0] in chain, "the customer's name is part of the file the store keeps"
    for value in NEVER_RECORDED[1:]:
        assert value not in chain, "contacts and reference never enter the store"


def test_store_ingest_refuses_another_engagement_s_file(tmp_path, capsys):
    first = write_engagement(tmp_path / "first")
    second = write_engagement(tmp_path / "second", id="other-2026-11")
    recording = _drive_under(first, tmp_path / "runs")
    database = tmp_path / "findings.sqlite"
    ingest = ["store", "ingest", "-q", "--store", str(database)]
    assert cli.main([*ingest, "--engagement", str(first), str(recording)]) == 0
    capsys.readouterr()

    code = cli.main([*ingest, "--engagement", str(second), str(recording)])

    assert code == 2
    assert "one store per engagement" in capsys.readouterr().err


def test_store_ingest_refuses_a_run_without_an_engagement_into_an_engagement_s_store(
    tmp_path, capsys
):
    held = write_engagement(tmp_path / "engagement")
    database = tmp_path / "findings.sqlite"
    under = _drive_under(held, tmp_path / "runs")
    assert cli.main(
        ["store", "ingest", "-q", "--store", str(database), "--engagement", str(held), str(under)]
    ) == 0  # fmt: skip
    plain_dir = tmp_path / "plain"
    assert cli.main(
        ["drive", "-q", "--manifest", str(MANIFEST), "--entry", "reference-server",
         "--isolation", "host", "--out-dir", str(plain_dir)]
    ) == 0  # fmt: skip
    capsys.readouterr()

    code = cli.main(
        ["store", "ingest", "-q", "--store", str(database), str(recording_in(plain_dir))]
    )

    assert code == 2
    assert "the run was made under no engagement" in capsys.readouterr().err


def test_a_refused_file_on_store_ingest_leaves_no_store_behind(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement", version=3)
    database = tmp_path / "findings.sqlite"

    code = cli.main(
        ["store", "ingest", "--store", str(database), "--engagement", str(held), "x.jsonl"]
    )

    assert code == 2
    assert not database.exists()


# -- engagement show ------------------------------------------------------------------------


def test_show_prints_the_file_with_its_digest_last_and_the_flag_still_needed(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement")

    assert cli.main(["engagement", "show", str(held)]) == 0

    said = capsys.readouterr()
    lines = said.out.rstrip("\n").splitlines()
    assert engagement.load(held).digest in lines[-1]
    assert "--engagement-confirmed is still needed" in said.out
    assert "read whole" in said.err


def test_show_json_reads_back_as_the_same_file(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement")

    assert cli.main(["engagement", "show", "--json", "-q", str(held)]) == 0

    shown = json.loads(capsys.readouterr().out)
    assert shown["digest"] == engagement.load(held).digest
    again = held.parent / "again.json"
    again.write_text(json.dumps(shown["engagement"]))
    reread = engagement.load(again)
    original = engagement.load(held)
    assert reread.data == original.data
    assert reread.window_declared() == original.window_declared()


def test_show_marks_a_draft_and_still_exits_zero(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement", customer="[CUSTOMER NAME]")

    assert cli.main(["engagement", "show", str(held)]) == 0

    said = capsys.readouterr()
    assert "customer" in said.out
    assert "a draft" in said.err


def test_show_refuses_a_file_it_cannot_read_whole(tmp_path, capsys):
    held = write_engagement(tmp_path / "engagement", unknown_key="x")

    assert cli.main(["engagement", "show", str(held)]) == 2
    said = capsys.readouterr()
    assert said.out == ""
    assert "unknown_key" in said.err


# -- fleet run --engagement -----------------------------------------------------------------


def test_a_fleet_the_file_does_not_cover_is_refused_before_docker_is_asked(
    tmp_path, monkeypatch, capsys
):
    def must_not_pin(*args, **kwargs):
        raise AssertionError("the images were pinned, which starts docker, before the refusal")

    def must_not_run(*args, **kwargs):
        raise AssertionError("the fleet was started although the file refuses it")

    monkeypatch.setattr(cli.fleet, "pin", must_not_pin)
    monkeypatch.setattr(cli.fleet, "run", must_not_run)
    held = write_engagement(tmp_path / "engagement", actions={"list": False, "call": False})
    out_dir = tmp_path / "fleets"

    code = cli.main(
        ["fleet", "run", "--manifest", str(MANIFEST), "--store", str(tmp_path / "s.sqlite"),
         "--out-dir", str(out_dir), "--engagement", str(held)]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert f"{held}: " in said and "lists_not_permitted" in said
    assert run_directories(out_dir) == []
    assert [record.reason for record in refusals_in(out_dir)] == ["lists_not_permitted"]
    assert not (tmp_path / "s.sqlite").exists(), "refused before the store was opened"


def test_a_fleet_under_a_file_hands_it_to_fleet_run(tmp_path, monkeypatch, capsys):
    seen = {}

    def stand_in_run(*args, **kwargs):
        seen.update(kwargs)
        raise cli.fleet.FleetError("stopped here by the test")

    monkeypatch.setattr(cli.fleet, "pin", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli.fleet, "run", stand_in_run)
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "fleets"

    code = cli.main(
        ["fleet", "run", "--manifest", str(MANIFEST), "--store", str(tmp_path / "s.sqlite"),
         "--out-dir", str(out_dir), "--engagement", str(held)]
    )  # fmt: skip

    assert code == 2
    assert seen["engagement"].digest == engagement.load(held).digest
    (record,) = refusals_in(out_dir)
    assert record.reason == "fleet"
    assert "stopped here by the test" in record.message


def test_a_fleet_without_a_file_hands_none_and_records_nothing(tmp_path, monkeypatch):
    seen = {}

    def stand_in_run(*args, **kwargs):
        seen.update(kwargs)
        raise cli.fleet.FleetError("stopped here by the test")

    monkeypatch.setattr(cli.fleet, "pin", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli.fleet, "run", stand_in_run)
    out_dir = tmp_path / "fleets"

    code = cli.main(
        ["fleet", "run", "--manifest", str(MANIFEST), "--store", str(tmp_path / "s.sqlite"),
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    assert seen["engagement"] is None
    assert not (out_dir / engagement.REFUSALS_FILE).exists()


def test_a_fleet_without_a_file_into_an_engagement_s_store_is_refused_before_docker(
    tmp_path, monkeypatch, capsys
):
    def must_not_pin(*args, **kwargs):
        raise AssertionError("the images were pinned, which starts docker, before the refusal")

    monkeypatch.setattr(cli.fleet, "pin", must_not_pin)
    held = write_engagement(tmp_path / "engagement")
    database = tmp_path / "findings.sqlite"
    with Store.open(database) as store:
        cli.set_engagement(store, engagement.load(held))
    out_dir = tmp_path / "fleets"

    code = cli.main(
        ["fleet", "run", "--manifest", str(MANIFEST), "--store", str(database),
         "--out-dir", str(out_dir)]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert "this store holds engagement acme-2026-10" in said
    assert "--engagement" in said
    assert run_directories(out_dir) == []


# -- the file never opens the gate, through the command line ---------------------------------


class PassedTheGate(Exception):
    """Raised where the run would prepare its destination: everything before it has let it by."""


def _outcome(argv, monkeypatch) -> str:
    def stop(*args, **kwargs):
        raise PassedTheGate

    monkeypatch.setattr(cli, "prepare_run", stop)
    try:
        code = cli.main(argv)
    except PassedTheGate:
        return "passed"
    assert code == 2
    return "refused"


@pytest.mark.parametrize("scenario", [False, True])
@pytest.mark.parametrize("target", [None, "127.0.0.1", "mcp.example.test"])
@pytest.mark.parametrize("confirmed", [False, True])
@pytest.mark.parametrize("acts", [False, True])
def test_no_file_lets_by_a_run_that_today_s_gate_refuses(
    scenario, target, confirmed, acts, tmp_path, monkeypatch, nothing_starts
):
    """For every combination of scenario, target, flag and a script that calls: with any file —
    one that lists everything and permits calls, and one that does not — a run is refused
    wherever it is refused without a file. Checked through ``cli.main``, so the order of the two
    gates in ``_main`` is what is tested, not a helper's."""
    open_file = write_engagement(
        tmp_path / "open",
        targets=[{"host": "127.0.0.1"}, {"host": "mcp.example.test", "paths": ["/mcp"]}],
        actions={"list": True, "call": True},
    )
    narrow_file = write_engagement(tmp_path / "narrow")
    script = tmp_path / "calls.json"
    script.write_text(
        json.dumps(
            {
                "version": 1,
                "name": "calls-one",
                "steps": ["initialize", {"list": "tools/list"}, {"call": {"tool": "echo"}}],
            }
        )
    )
    argv = ["drive", "--out-dir", str(tmp_path / "runs")]
    if scenario:
        argv += ["--scenario", str(open_file.parent / "all-signals.yaml")]
    if target is not None:
        argv += ["--target", target]
    if confirmed:
        argv += ["--engagement-confirmed"]
    if acts:
        argv += ["--script", str(script)]
    command = ["--", sys.executable, DISCOVERY]

    without = _outcome([*argv, *command], monkeypatch)
    for held in (open_file, narrow_file):
        under = _outcome([*argv, "--engagement", str(held), *command], monkeypatch)
        if without == "refused":
            assert under == "refused", f"{held.parent.name} let by what today's gate refuses"
    assert nothing_starts == []


def test_every_condition_is_reached_through_the_command_line():
    reached = set(CONDITION_CASES) | {
        "below_isolation",  # test_below_isolation_refuses_a_corpus_run_under_a_weaker_isolation
        "path_not_listed",  # test_path_not_listed_refuses_an_http_run_before_anything_connects
        "calls_not_permitted",  # test_calls_not_permitted_refuses_a_script_that_calls
        # tests/test_identities.py, each through cli.main
        "identity_not_declared",
        "identity_required",
        "token_not_declared",
        "token_source_differs",
        # tests/test_scope_guard.py, each through cli.main
        "tool_not_listed",
        "tool_writes_not_released",
        "tool_denied",
        # tests/test_active_probes.py, each through cli.main
        "stop_file",
        "probe_not_listed",
        # tests/test_personal_data.py, through cli.main
        "salt_missing",
        "salt_too_short",
    }
    assert reached == set(engagement.CONDITIONS)


# -- every other refusal after the file is read is written down under its own reason ----------


def _refused_with_reason(tmp_path, capsys, argv, reason) -> str:
    held = write_engagement(tmp_path / "engagement")
    out_dir = tmp_path / "runs"
    code = cli.main(["drive", "--engagement", str(held), "--out-dir", str(out_dir), *argv])
    assert code == 2
    assert [record.reason for record in refusals_in(out_dir)] == [reason]
    assert run_directories(out_dir) == []
    return capsys.readouterr().err


def test_http_options_are_written_down(tmp_path, capsys, nothing_starts):
    said = _refused_with_reason(
        tmp_path, capsys, ["--http", "http://127.0.0.1:9/mcp", "--", sys.executable, TOY],
        "http_options",
    )  # fmt: skip
    assert "drop the -- command" in said


def test_a_manifest_refusal_is_written_down(tmp_path, capsys, nothing_starts):
    said = _refused_with_reason(
        tmp_path, capsys, ["--manifest", str(MANIFEST), "--entry", "no-such-entry"], "manifest"
    )
    assert "no-such-entry" in said


def test_an_argument_refusal_is_written_down(tmp_path, capsys, nothing_starts):
    said = _refused_with_reason(
        tmp_path, capsys, ["--isolation", "host", "--", sys.executable, TOY], "arguments"
    )
    assert "--isolation belongs to a corpus run" in said


def test_a_script_refusal_is_written_down(tmp_path, capsys, nothing_starts):
    _refused_with_reason(
        tmp_path, capsys, ["--script", str(tmp_path / "missing.json"), "--", sys.executable, TOY],
        "script",
    )  # fmt: skip


def test_a_scenario_with_rules_over_http_is_written_down(tmp_path, capsys, monkeypatch):
    def must_not_connect(*args, **kwargs):
        raise AssertionError("nothing may connect when the run is refused")

    monkeypatch.setattr("socket.create_connection", must_not_connect)
    said = _refused_with_reason(
        tmp_path, capsys,
        ["--http", "http://127.0.0.1:9/mcp", "--scenario",
         str(FIXTURES / "scenarios" / "tool-poisoning.yaml")],
        "scenario_over_http",
    )  # fmt: skip
    assert "--http observes only" in said


def test_an_identity_refusal_is_written_down(tmp_path, capsys, nothing_starts):
    _refused_with_reason(
        tmp_path, capsys,
        ["--server-content", str(tmp_path / "missing.py"), "--", sys.executable, DISCOVERY],
        "identity",
    )  # fmt: skip


def test_a_delivery_refusal_is_written_down(tmp_path, capsys, monkeypatch, nothing_starts):
    def cannot_deliver(*args, **kwargs):
        raise cli.SandboxFailed("staged", "failed in the test")

    monkeypatch.setattr(
        cli, "pin_images", lambda *a: {"sandbox_image": ("s", None), "target_image": ("t", None)}
    )
    monkeypatch.setattr(cli, "stage", cannot_deliver)
    said = _refused_with_reason(
        tmp_path, capsys,
        ["--manifest", str(MANIFEST), "--entry", "reference-server", "--isolation", "runc"],
        "delivery",
    )  # fmt: skip
    assert "the entry's files cannot be delivered" in said


def test_a_refused_destination_cannot_be_written_down_and_says_so(tmp_path, capsys, nothing_starts):
    """The destination is refused by the same check the record would pass through, so its
    refusal is the one that is said and never written: the terminal says that too."""
    git = shutil.which("git")
    assert git, "this test needs a git binary"
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run([git, "init", "-q", "-b", "main"], cwd=repo, check=True)  # noqa: S603
    held = write_engagement(tmp_path / "engagement")

    code = cli.main(
        ["drive", "--engagement", str(held), "--out-dir", str(repo / "runs"), "--",
         sys.executable, DISCOVERY]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert "git working tree" in said
    assert f"the refusal is not written to {engagement.REFUSALS_FILE}" in said
    assert not (repo / "runs").exists()


def test_a_store_that_cannot_be_opened_for_a_fleet_is_written_down(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli.fleet, "pin", lambda *args, **kwargs: None)
    held = write_engagement(tmp_path / "engagement")
    not_a_store = tmp_path / "notes.sqlite"
    with contextlib.closing(sqlite3.connect(not_a_store)) as connection:
        connection.execute("CREATE TABLE notes (text TEXT)")
    out_dir = tmp_path / "fleets"

    code = cli.main(
        ["fleet", "run", "--manifest", str(MANIFEST), "--store", str(not_a_store),
         "--out-dir", str(out_dir), "--engagement", str(held)]
    )  # fmt: skip

    assert code == 2
    assert "names no store schema" in capsys.readouterr().err
    assert [record.reason for record in refusals_in(out_dir)] == ["store"]


def test_a_full_refusals_log_still_refuses_and_says_this_refusal_was_not_written(
    tmp_path, monkeypatch, capsys, nothing_starts
):
    """A log at its cap never turns a refusal into a run or into a silent refusal: exit 2, the
    refusal's words, and a line saying the log is full and this one was not written."""
    held = write_engagement(tmp_path / "engagement", actions={"list": False, "call": False})
    out_dir = tmp_path / "runs"
    argv = ["drive", "--engagement", str(held), "--out-dir", str(out_dir), "--", sys.executable,
            DISCOVERY]  # fmt: skip
    assert cli.main(argv) == 2
    log = out_dir / engagement.REFUSALS_FILE
    monkeypatch.setattr(engagement, "MAX_REFUSALS_BYTES", log.stat().st_size + 10)
    before = log.read_bytes()
    capsys.readouterr()

    code = cli.main(argv)

    assert code == 2
    assert nothing_starts == []
    assert run_directories(out_dir) == []
    said = capsys.readouterr().err
    assert "lists_not_permitted" in said
    assert f"the refusal is not written to {engagement.REFUSALS_FILE}" in said
    assert "is full" in said
    assert log.read_bytes() == before
