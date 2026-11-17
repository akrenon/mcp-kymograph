"""Ctrl-C during a fleet: every run it started is stopped, nothing is left running, and what had
already ended is filed — the fleet itself is filed as interrupted and incomplete.

With real processes, without Docker: the fleet runs as a process of its own and is sent the
signal, and each of its runs is a stand-in for ``drive`` that behaves as a run would — one ends
before the interruption with a recording, one stops when asked, one has to be killed, one is
still queued. Each stand-in starts a child in its process group, as a run starts its sink, so
that "nothing left" covers the run's own children too. The same under runc, with real drives
and real containers, is in ``test_fleet_interrupt_docker`` below.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from mcp_kymograph import fleet, verdict
from mcp_kymograph.store import Store
from test_fleet import CONSISTENT, PINS, docker, write_manifest
from test_store import recording

#: A stand-in for ``kymograph drive``: takes its arguments, logs its pid and its child's, and
#: does what its entry's name says.
FAKE_DRIVE = r"""
import json, os, shutil, signal, subprocess, sys, time
from pathlib import Path

args = sys.argv[1:]
value = lambda flag: args[args.index(flag) + 1]
out, entry, nonce = Path(value("--out-dir")), value("--entry"), value("--sandbox-nonce")
log = Path(os.environ["FAKE_DRIVE_LOG"])

def say(**what):
    with log.open("a") as f:
        f.write(json.dumps({"entry": entry, **what}) + "\n")

child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
if entry == "finished":
    child.kill()
    (out / "run").mkdir(parents=True)
    shutil.copyfile(os.environ["FAKE_READY"], out / "run" / "events.jsonl")
    say(pid=os.getpid(), child=child.pid, nonce=nonce)
    sys.exit(0)

def stop(number, frame):
    child.kill()
    (out / "run").mkdir(parents=True)
    (out / "run" / "events.jsonl").write_text('{"type": "run_started"}\n')
    say(event="terminated")
    sys.exit(3)

signal.signal(signal.SIGTERM, signal.SIG_IGN if entry == "stubborn" else stop)
say(pid=os.getpid(), child=child.pid, nonce=nonce)
while True:
    time.sleep(1)
"""

#: The fleet, on the command line, with the stand-in for drive and without Docker.
FLEET = r"""
import json, sys
from mcp_kymograph import cli, fleet

fleet.DRIVE = (sys.executable, sys.argv[1])
fleet.pin = lambda *_: fleet.Pins("runc", *json.loads(sys.argv[2]))
fleet.clean_up_after = lambda nonce: [f"cleaned up after {nonce}"]
fleet.INTERRUPT_GRACE = float(sys.argv[3])
sys.exit(cli.main(sys.argv[4:]))
"""

ENTRIES = ("finished", "polite", "stubborn", "queued", "never")


def gone(pid: int) -> bool:
    """No such process, or one that has ended and waits only to be reaped."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return True
    return stat.rsplit(")", 1)[1].split()[0] == "Z"


def logged(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def start_fleet(tmp_path: Path, entries, *, grace: float, parallel: int):
    manifest = write_manifest(tmp_path, *({"name": name} for name in entries))
    ready = recording(tmp_path, [], name="ready", entry="finished", isolation="runc",
                      sandbox_image=PINS.sandbox_image, target_image=PINS.target_image,
                      extra=[CONSISTENT])  # fmt: skip
    (tmp_path / "drive.py").write_text(FAKE_DRIVE)
    (tmp_path / "fleet.py").write_text(FLEET)
    log = tmp_path / "drive.log"
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, str(tmp_path / "fleet.py"), str(tmp_path / "drive.py"),
         json.dumps([PINS.sandbox_image, PINS.target_image]), str(grace),
         "fleet", "run", "--manifest", str(manifest), "--store", str(tmp_path / "s.sqlite"),
         "--out-dir", str(tmp_path / "runs"), "--parallel", str(parallel)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "FAKE_DRIVE_LOG": str(log), "FAKE_READY": str(ready)},
    )  # fmt: skip
    return process, log


def wait_for(condition, *, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("timed out waiting")
        time.sleep(0.05)


def started(log: Path) -> set[str]:
    return {line["entry"] for line in logged(log) if "pid" in line}


def kill_what_was_logged(log: Path) -> None:
    """Whatever happens in the test, no stand-in outlives it: the stubborn one sleeps forever."""
    for line in logged(log):
        for pid in (line.get("pid"), line.get("child")):
            if pid is not None and not gone(pid):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize("number", [signal.SIGINT, signal.SIGTERM], ids=["SIGINT", "SIGTERM"])
def test_an_interrupted_fleet_stops_every_run_files_what_ended_and_leaves_nothing_running(
    tmp_path, number
):
    process, log = start_fleet(tmp_path, ENTRIES, grace=1.5, parallel=3)
    try:
        # Three slots: "finished" ends at once and "queued" takes its place; "never" waits.
        wait_for(lambda: started(log) == {"finished", "polite", "stubborn", "queued"})
        time.sleep(0.5)  # "finished" is filed by the fleet before the signal
        process.send_signal(number)
        out, err = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
        pids_seen = [
            p for line in logged(log) if "pid" in line for p in (line["pid"], line["child"])
        ]
        with contextlib.suppress(AssertionError):  # a child killed with its group may lag
            wait_for(lambda: all(gone(pid) for pid in pids_seen), timeout=5)
        alive_after = [pid for pid in pids_seen if not gone(pid)]
        kill_what_was_logged(log)
    name = signal.Signals(number).name
    assert b"Traceback" not in err, err.decode()
    assert process.returncode == verdict.EXIT_INCOMPLETE, err.decode()
    record = json.loads(out)["fleet"]
    assert record["interrupted"] == name
    assert record["state"] == verdict.INCOMPLETE and record["complete"] is False
    assert f"interrupted by {name}: 3 run(s) stopped and 1 never started" in record["problems"][0]
    results = {r["entry"]: r for r in record["results"]}

    assert (results["finished"]["state"], results["finished"]["causes"]) == ("complete", [])
    for entry in ("polite", "stubborn", "queued"):
        result = results[entry]
        assert (result["state"], result["causes"], result["run"]) == (
            "unfiled",
            ["interrupted"],
            None,
        )
        assert result["problems"][0] == f"stopped: the fleet was interrupted ({name})"
        assert any(p.startswith("cleaned up after ") for p in result["problems"]), result
    assert results["polite"]["exit_code"] == 3, "asked first: it stopped on SIGTERM"
    assert results["queued"]["exit_code"] == 3
    assert results["stubborn"]["exit_code"] == -signal.SIGKILL, "made to stop when it would not"
    assert any("its recording is not filed" in p for p in results["polite"]["problems"])
    never = results["never"]
    assert (never["state"], never["causes"], never["exit_code"]) == (
        "unfiled",
        ["interrupted"],
        None,
    )
    assert never["problems"] == [f"not started: the fleet was interrupted ({name})"]
    assert not any(p.startswith("cleaned up") for p in results["finished"]["problems"])

    assert "never" not in started(log), "no run starts once the fleet is interrupted"
    assert len(pids_seen) == 8
    assert alive_after == [], "every run and its child ended with the fleet"

    with Store.open(tmp_path / "s.sqlite") as store:
        (filed,) = store.fleets()
        assert [run.state for run in store.runs()] == ["complete"], "only what had ended is filed"
    assert filed["complete"] is False
    assert {e: r["causes"] for (e, _), r in filed["results"].items()} == {
        "finished": [], "polite": ["interrupted"], "stubborn": ["interrupted"],
        "queued": ["interrupted"], "never": ["interrupted"],
    }  # fmt: skip
    assert filed["problems"][0].startswith(f"interrupted by {name}")


def test_a_second_interruption_makes_the_stop_immediate(tmp_path):
    process, log = start_fleet(tmp_path, ["stubborn"], grace=120.0, parallel=1)
    try:
        wait_for(lambda: started(log) == {"stubborn"})
        process.send_signal(signal.SIGINT)
        time.sleep(1.0)
        began = time.monotonic()
        process.send_signal(signal.SIGINT)
        out, err = process.communicate(timeout=60)
        took = time.monotonic() - began
    finally:
        if process.poll() is None:
            process.kill()
        kill_what_was_logged(log)
    assert b"Traceback" not in err, err.decode()
    assert took < 20, f"the second Ctrl-C waited {took:.1f} s for a grace of 120 s"
    (result,) = json.loads(out)["fleet"]["results"]
    assert result["exit_code"] == -signal.SIGKILL
    (line,) = [entry for entry in logged(log) if "pid" in entry]
    assert gone(line["pid"]) and gone(line["child"])


def test_the_fleet_gives_the_signal_handlers_back_when_it_is_done(tmp_path):
    from test_fleet import launcher, pair

    before = {number: signal.getsignal(number) for number in fleet.INTERRUPTS}
    with Store.open(tmp_path / "s.sqlite") as store:
        plan = launcher({"reference-server": {}, "poison-server": {}})
        record = fleet.run(pair(tmp_path), store, tmp_path / "runs", pins=PINS, launcher=plan)
    assert record.interrupted is None and record.state == verdict.COMPLETE
    assert {number: signal.getsignal(number) for number in fleet.INTERRUPTS} == before


@docker
@pytest.mark.parametrize("grace", [fleet.INTERRUPT_GRACE, 0.0], ids=["asked", "killed"])
def test_fleet_interrupt_docker_leaves_no_run_no_container_and_no_staging_directory(
    tmp_path, grace
):
    """Real drives under runc, each with a target that never answers. Ctrl-C while every target
    runs: asked to stop, each run removes its own containers; killed at once (grace 0), the
    fleet removes them by the run's nonce. Either way nothing of any run is left."""
    from mcp_kymograph.sandbox import docker as docker_cli

    manifest = write_manifest(
        tmp_path,
        *({"name": f"hanging-{n}", "command": ["{python}", "-c", "import time; time.sleep(300)"]}
          for n in range(3)),
    )  # fmt: skip
    staged_before = set(Path(tempfile.gettempdir()).glob("mcp-kymograph-stage-*"))
    containers_before = set(docker_cli.leftovers("mcp-kymograph.run"))
    script = tmp_path / "fleet.py"
    script.write_text(
        "import sys\nfrom mcp_kymograph import cli, fleet\n"
        "fleet.INTERRUPT_GRACE = float(sys.argv[1])\nsys.exit(cli.main(sys.argv[2:]))\n"
    )
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, str(script), str(grace), "fleet", "run", "--manifest", str(manifest),
         "--store", str(tmp_path / "s.sqlite"), "--out-dir", str(tmp_path / "runs"),
         "--parallel", "2", "--step-timeout", "240", "-q"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )  # fmt: skip

    seen: dict[int, str] = {}

    def targets_running() -> bool:
        seen.update(_drives_of(process.pid))
        nonces = set(_drives_of(process.pid).values())
        return len(nonces) == 2 and all(
            docker_cli.checked(["ps", "-q", "--filter", f"label=mcp-kymograph.run={nonce}",
                                "--filter", "label=mcp-kymograph.role=target"], timeout=30).strip()
            for nonce in nonces
        )  # fmt: skip

    try:
        wait_for(targets_running, timeout=180)
        nonces = set(_drives_of(process.pid).values())
        process.send_signal(signal.SIGINT)
        out, err = process.communicate(timeout=120)
    finally:
        if process.poll() is None:
            process.kill()
        # Whatever the outcome, no drive of this test outlives it — a failed run of this test
        # must not leave runs behind that the next one would count as its own.
        for pid, nonce in seen.items():
            with contextlib.suppress(OSError):  # only while the pid is still that drive
                if nonce.encode() in Path(f"/proc/{pid}/cmdline").read_bytes():
                    os.killpg(pid, signal.SIGKILL)
            from mcp_kymograph.sandbox.runner import clean_up_after

            clean_up_after(nonce)
    assert b"Traceback" not in err, err.decode()
    assert process.returncode == verdict.EXIT_INCOMPLETE, err.decode()
    record = json.loads(out)["fleet"]
    assert record["interrupted"] == "SIGINT"
    states = sorted((r["state"], r["causes"][0], r["problems"][0].split(":")[0])
                    for r in record["results"])  # fmt: skip
    assert states == [("unfiled", "interrupted", "not started"),
                      ("unfiled", "interrupted", "stopped"),
                      ("unfiled", "interrupted", "stopped")]  # fmt: skip
    assert [pid for pid in seen if not gone(pid)] == [], "no drive may be left running"
    for nonce in nonces:
        assert docker_cli.leftovers(f"mcp-kymograph.run={nonce}") == []
        assert list(Path(tempfile.gettempdir()).glob(f"mcp-kymograph-stage-{nonce}-*")) == []
    assert set(Path(tempfile.gettempdir()).glob("mcp-kymograph-stage-*")) <= staged_before
    assert set(docker_cli.leftovers("mcp-kymograph.run")) <= containers_before
    if grace == 0.0:
        said = [p for r in record["results"] for p in r["problems"]]
        assert any("container(s) behind; removed" in p for p in said), said


def _drives_of(fleet: int) -> dict[int, str]:
    """The drives this fleet started that are still running, by pid, with their nonce — read
    from /proc: the drive's parent and its command line."""
    found = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except OSError:
            continue
        state, parent = fields[0], int(fields[1])
        if parent == fleet and state != "Z" and b"--sandbox-nonce" in argv:
            found[int(entry.name)] = argv[argv.index(b"--sandbox-nonce") + 1].decode()
    return found


def test_launch_hands_every_run_a_nonce_of_its_own(tmp_path, monkeypatch):
    from mcp_kymograph.corpus import load as load_manifest
    from test_fleet import PROJECT

    seen = []

    class Done:
        pid = -1
        returncode = 0

        def communicate(self, timeout=None):
            return b"", b""

    monkeypatch.setattr(fleet.subprocess, "Popen", lambda argv, **_: seen.append(argv) or Done())
    job = fleet.plan(load_manifest(PROJECT))[0]
    for _ in range(2):
        fleet.launch(job, PINS, PROJECT, tmp_path / "out", step_timeout=2.0, job_timeout=9.0)
    nonces = [argv[argv.index("--sandbox-nonce") + 1] for argv in seen]
    assert len(set(nonces)) == 2
    assert all(len(n) == 12 and set(n) <= set("0123456789abcdef") for n in nonces)


def test_the_nonce_names_the_staging_directory(tmp_path):
    from mcp_kymograph.identity import from_content
    from mcp_kymograph.sandbox import runner

    server = tmp_path / "server.py"
    server.write_text("print(1)\n")
    delivery = runner.stage([server], from_content([server]), tmp_path, ["{python}", "server.py"],
                            nonce="0123456789ab")  # fmt: skip
    try:
        assert delivery.directory.name.startswith("mcp-kymograph-stage-0123456789ab-")
    finally:
        delivery.cleanup()


def test_what_a_killed_run_left_is_found_by_its_nonce_and_removed(tmp_path, monkeypatch):
    from mcp_kymograph.sandbox import docker as docker_cli
    from mcp_kymograph.sandbox import runner

    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(tmp_path))
    (tmp_path / "mcp-kymograph-stage-0123456789ab-x1y2").mkdir()
    (tmp_path / "mcp-kymograph-stage-ba9876543210-other").mkdir()
    listed = [["c1", "c2"], []]
    removed = []
    monkeypatch.setattr(runner.docker, "leftovers", lambda label: listed.pop(0))
    monkeypatch.setattr(runner.docker, "remove", removed.extend)
    said = runner.clean_up_after("0123456789ab")
    assert removed == ["c1", "c2"]
    assert said == [
        "the stopped run left 2 container(s) behind; removed",
        "the stopped run left its staging directory behind; removed",
    ]
    assert [p.name for p in tmp_path.iterdir()] == ["mcp-kymograph-stage-ba9876543210-other"]

    def unreachable(label):
        raise docker_cli.DockerError("docker could not be run: No such file or directory")

    monkeypatch.setattr(runner.docker, "leftovers", unreachable)
    (said,) = runner.clean_up_after("0123456789ab")
    assert said.startswith("whether the stopped run left containers behind could not be checked")


@pytest.mark.parametrize("value", ["", "0123456789a", "0123456789ABC", "0123456789AB", "xyz"])
def test_a_nonce_that_is_not_twelve_lowercase_hex_digits_is_an_input_error(value, capsys):
    from mcp_kymograph import cli

    with pytest.raises(SystemExit) as refused:
        cli.main(["drive", "--sandbox-nonce", value, "--", "srv"])
    assert refused.value.code == cli.EXIT_REFUSED
    assert "argument --sandbox-nonce" in capsys.readouterr().err


def test_a_nonce_belongs_to_a_run_under_runc(tmp_path, capsys):
    from mcp_kymograph import cli

    code = cli.main(["drive", "--out-dir", str(tmp_path / "runs"), "--sandbox-nonce",
                     "0123456789ab", "--", sys.executable, "-c", "pass"])  # fmt: skip
    assert code == cli.EXIT_REFUSED
    assert "--sandbox-nonce belongs to a run under --isolation runc" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_once_the_fleet_is_stopping_no_run_starts(tmp_path):
    """A worker that took its job just before the interruption must not start it after: the
    stop closes the door first, and the run is recorded as never started."""
    from mcp_kymograph.corpus import load as load_manifest
    from test_fleet import PROJECT

    processes = fleet.Processes()
    assert processes.stop(0.1) == 0
    assert processes.start([sys.executable, "-c", "raise SystemExit(9)"]) is None
    job = fleet.plan(load_manifest(PROJECT))[0]
    launched = fleet.launch(job, PINS, PROJECT, tmp_path / "out", step_timeout=2.0,
                            job_timeout=9.0, processes=processes)  # fmt: skip
    assert (launched.exit_code, launched.interrupted) == (None, fleet.NOT_STARTED)
    assert not (tmp_path / "out").exists()
