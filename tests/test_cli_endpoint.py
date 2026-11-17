"""An endpoint entry on the command line: ``drive --manifest M --entry E`` against a server
someone else runs, and every way such a run is refused before anything connects.

The run is the loopback HTTP test server (tests/fixtures/http_server.py); every refused run
names a host that is not local and is checked to open no connection at all.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path

import pytest

from mcp_kymograph import cli, engagement
from mcp_kymograph.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))

import http_server  # noqa: E402

ALL_SIGNALS = FIXTURES / "scenarios" / "all-signals.yaml"
CORPUS = FIXTURES / "corpus" / "manifest.yaml"


@pytest.fixture
def poison_url():
    server = http_server.serve(0, variant="poison")
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}{http_server.PATH}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def nothing_connects(monkeypatch):
    """Fails the test at its end if anything tried to connect or to resolve a name — kept in a
    list, because the HTTP channel catches what it is raised and reads it as unreachable."""
    attempts: list[tuple] = []

    def must_not_connect(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("a connection was opened although the run was refused")

    monkeypatch.setattr(socket, "create_connection", must_not_connect)
    monkeypatch.setattr(socket.socket, "connect", must_not_connect)
    monkeypatch.setattr(socket, "getaddrinfo", must_not_connect)
    yield
    assert attempts == [], f"a connection or a name lookup was attempted: {attempts!r}"


def endpoint_manifest(directory: Path, url: str, version_declared: str | None = "3.1") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    source = {"endpoint": url}
    if version_declared is not None:
        source["version_declared"] = version_declared
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "name": "customer-mcp",
                        "provenance": "real-world",
                        "source": source,
                        "launch": {"transport": "streamable-http"},
                        "scenarios": [os.path.relpath(ALL_SIGNALS, directory)],
                    }
                ],
            }
        )
    )
    return path


def engagement_file(directory: Path) -> Path:
    """A file in its window that lists ``mcp.example.test`` with the path ``/mcp`` and no port
    (443, the port of https, for a URL), and the scenario the endpoint manifest names."""
    directory.mkdir()
    now = datetime.now(timezone.utc)
    held = directory / "engagement.json"
    held.write_text(
        json.dumps(
            {
                "version": 1,
                "id": "acme-2026-10",
                "window": {
                    "from": (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "until": (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                "targets": [{"host": "mcp.example.test", "paths": ["/mcp"]}],
                "scenarios": [
                    {"path": os.path.relpath(ALL_SIGNALS, directory),
                     "sha256": sha256(ALL_SIGNALS.read_bytes()).hexdigest()}
                ],
                "actions": {"list": True, "call": False},
            }
        )
    )  # fmt: skip
    return held


def drive(manifest: Path, out_dir: Path, *extra: str) -> int:
    return cli.main(
        ["drive", "-q", "--manifest", str(manifest), "--entry", "customer-mcp", "--out-dir",
         str(out_dir), *extra]
    )  # fmt: skip


def test_an_endpoint_entry_is_driven_over_http_under_remote_and_filed_declared(
    tmp_path, poison_url, capsys
):
    manifest = endpoint_manifest(tmp_path / "manifest", poison_url)
    out_dir = tmp_path / "runs"

    assert drive(manifest, out_dir) == 0

    said = capsys.readouterr().err
    assert "egress not observed (isolation remote)" in said
    (recording,) = out_dir.glob("*/events.jsonl")
    started = json.loads(recording.read_text().splitlines()[0])
    assert started["transport"] == "streamable-http"
    assert started["isolation"] == "remote"
    assert started["reproduction"]["corpus"]["entry"] == "customer-mcp"
    assert started["reproduction"]["corpus"]["identity"]["kind"] == "endpoint"
    assert started["reproduction"]["environment"]["isolation"] == "remote"

    database = tmp_path / "findings.sqlite"
    assert cli.main(["store", "ingest", "-q", "--store", str(database), str(recording)]) == 0
    capsys.readouterr()
    assert cli.main(["store", "runs", "--store", str(database)]) == 0
    (run,) = json.loads(capsys.readouterr().out)
    assert run["isolation"] == "remote"
    assert run["server_version"] == "3.1"
    assert run["server_version_kind"] == "declared"
    assert run["egress_observed"] is False


def test_a_non_local_plain_http_endpoint_is_refused_even_to_observe(
    tmp_path, nothing_connects, capsys
):
    """Plain HTTP to a host that is not a loopback literal is refused before the gate is asked;
    the gate's own rule for a non-local endpoint is tested where TLS is spoken."""
    manifest = endpoint_manifest(tmp_path / "manifest", "http://mcp.example.test:80/mcp")

    code = drive(manifest, tmp_path / "runs")

    assert code == 2
    assert "which is not a loopback address" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_a_non_local_endpoint_needs_the_confirmation_even_to_observe(
    tmp_path, nothing_connects, capsys
):
    """Over https:// the gate's own rule holds: an endpoint entry runs a scenario, and its host
    is not local, so it needs the confirmation; nothing connects before it is given."""
    manifest = endpoint_manifest(tmp_path / "manifest", "https://mcp.example.test:443/mcp")

    code = drive(manifest, tmp_path / "runs")

    assert code == 2
    said = capsys.readouterr().err
    assert "--engagement-confirmed" in said
    assert "which is not a loopback address" not in said
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize(
    ("extra", "words"),
    [
        (["--isolation", "runc"], "nothing here to run"),
        (["--isolation", "host"], "nothing here to run"),
        (["--sandbox-image", "x:1"], "belong to a run under --isolation runc"),
        (["--http", "http://127.0.0.1:9/mcp"], "--http cannot be combined with --manifest"),
    ],
)
def test_an_endpoint_entry_refuses_what_belongs_to_a_server_run_here(
    tmp_path, nothing_connects, capsys, extra, words
):
    manifest = endpoint_manifest(tmp_path / "manifest", "http://127.0.0.1:9/mcp")

    code = drive(manifest, tmp_path / "runs", *extra)

    assert code == 2
    assert words in capsys.readouterr().err


def test_a_command_entry_never_runs_under_remote(tmp_path, capsys):
    code = cli.main(
        ["drive", "--manifest", str(CORPUS), "--entry", "reference-server", "--isolation",
         "remote", "--out-dir", str(tmp_path / "runs")]
    )  # fmt: skip

    assert code == 2
    assert "never runs under remote" in capsys.readouterr().err


def test_a_plain_http_endpoint_under_a_file_is_refused_as_plain_http_before_its_path(
    tmp_path, nothing_connects, capsys
):
    """The path is not listed, and the URL is plain HTTP to another host: the plain-HTTP rule
    comes first and is what the refusal records."""
    manifest = endpoint_manifest(tmp_path / "manifest", "http://mcp.example.test:80/other")
    held = engagement_file(tmp_path / "engagement")
    out_dir = tmp_path / "runs"

    code = drive(manifest, out_dir, "--engagement", str(held), "--engagement-confirmed")

    assert code == 2
    assert "which is not a loopback address" in capsys.readouterr().err
    (record,) = engagement.read_refusals(out_dir / engagement.REFUSALS_FILE)
    assert record.reason == "plain_http"


def test_an_endpoint_path_the_engagement_does_not_list_is_refused_before_connecting(
    tmp_path, nothing_connects, capsys
):
    """Over https:// the plain-HTTP rule does not apply, and the file's own conditions are what
    refuse: the port is the default the file is read as covering, the path is not listed."""
    manifest = endpoint_manifest(tmp_path / "manifest", "https://mcp.example.test:443/other")
    held = engagement_file(tmp_path / "engagement")
    out_dir = tmp_path / "runs"

    code = drive(manifest, out_dir, "--engagement", str(held), "--engagement-confirmed")

    assert code == 2
    assert f"{held}: path_not_listed: " in capsys.readouterr().err
    (record,) = engagement.read_refusals(out_dir / engagement.REFUSALS_FILE)
    assert record.reason == "path_not_listed"
    assert [p.name for p in out_dir.iterdir()] == [engagement.REFUSALS_FILE]


def test_a_fleet_over_a_manifest_with_an_endpoint_entry_is_refused(
    tmp_path, monkeypatch, nothing_connects, capsys
):
    def must_not_pin(*args, **kwargs):
        raise AssertionError("the images were pinned, which starts docker, before the refusal")

    monkeypatch.setattr(cli.fleet, "pin", must_not_pin)
    manifest = endpoint_manifest(tmp_path / "manifest", "http://127.0.0.1:9/mcp")

    code = cli.main(
        ["fleet", "run", "--manifest", str(manifest), "--store", str(tmp_path / "s.sqlite"),
         "--out-dir", str(tmp_path / "fleets")]
    )  # fmt: skip

    assert code == 2
    said = capsys.readouterr().err
    assert "endpoint entry 'customer-mcp'" in said
    assert "drive only" in said
    assert not (tmp_path / "fleets").exists()


def test_corpus_check_names_the_endpoint_and_remote(tmp_path, capsys):
    manifest = endpoint_manifest(tmp_path / "manifest", "http://127.0.0.1:9/mcp")

    assert cli.main(["corpus", "check", "-q", str(manifest)]) == 0

    (entry,) = json.loads(capsys.readouterr().out)["entries"]
    assert entry["transport"] == "streamable-http"
    assert entry["endpoint"] == "http://127.0.0.1:9/mcp"
    assert entry["isolation_permitted"] == ["remote"]
    assert entry["command"] == []


def test_a_store_of_endpoint_runs_is_still_one_store_per_engagement(tmp_path, poison_url):
    """Nothing about an endpoint run widens what a store takes: a store without an engagement
    takes it as it takes any run without one."""
    manifest = endpoint_manifest(tmp_path / "manifest", poison_url, version_declared=None)
    assert drive(manifest, tmp_path / "runs") == 0
    (recording,) = (tmp_path / "runs").glob("*/events.jsonl")

    with Store.open(tmp_path / "findings.sqlite") as store:
        filed = store.ingest(recording)
        (run,) = store.runs()

    assert filed.state == "complete"
    assert run.server_version == "endpoint"
    assert run.to_dict()["server_version_kind"] == "declared"


# -- edge cases of endpoint runs ------------------------------------------------------------


def test_a_plain_http_run_says_its_egress_is_not_observed_without_claiming_a_child(
    tmp_path, poison_url, capsys
):
    assert cli.main(["drive", "-q", "--http", poison_url, "--out-dir", str(tmp_path / "r")]) == 0

    said = capsys.readouterr().err
    assert "egress not observed (isolation host): the server runs elsewhere" in said
    assert "child" not in said


def test_verdict_and_ingest_say_a_remote_run_s_egress_is_not_observed(tmp_path, poison_url, capsys):
    manifest = endpoint_manifest(tmp_path / "manifest", poison_url)
    assert drive(manifest, tmp_path / "runs") == 0
    (recording,) = (tmp_path / "runs").glob("*/events.jsonl")
    capsys.readouterr()

    assert cli.main(["verdict", str(recording)]) == 0
    said = capsys.readouterr()
    judged = json.loads(said.out)
    assert judged["isolation"] == "remote"
    assert judged["egress_observed"] is False
    assert "egress not observed (isolation remote)" in said.err

    database = tmp_path / "findings.sqlite"
    assert cli.main(["store", "ingest", "--store", str(database), str(recording)]) == 0
    assert "egress not observed (isolation remote)" in capsys.readouterr().err


def test_an_endpoint_isolation_refusal_names_the_manifest(tmp_path, nothing_connects, capsys):
    manifest = endpoint_manifest(tmp_path / "manifest", "http://127.0.0.1:9/mcp")

    assert drive(manifest, tmp_path / "runs", "--isolation", "runc") == 2
    assert "manifest.json" in capsys.readouterr().err


def test_a_declared_version_may_not_be_the_word_an_undeclared_one_reads(tmp_path, capsys):
    manifest = endpoint_manifest(tmp_path / "manifest", "http://127.0.0.1:9/mcp", "endpoint")

    assert cli.main(["corpus", "check", str(manifest)]) == 2
    assert "version_declared" in capsys.readouterr().err


def test_a_scenario_over_plain_http_against_a_non_local_host_is_refused_by_the_rule(
    tmp_path, nothing_connects, capsys
):
    """drive --http with a scenario against another host over plain HTTP is refused by the
    plain-HTTP rule before the gate would ask for the confirmation."""
    code = cli.main(
        ["drive", "--http", "http://mcp.example.test:80/mcp", "--scenario", str(ALL_SIGNALS),
         "--out-dir", str(tmp_path / "runs")]
    )  # fmt: skip

    assert code == 2
    assert "which is not a loopback address" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_a_scenario_over_https_against_a_non_local_host_needs_the_confirmation(
    tmp_path, nothing_connects, capsys
):
    """One rule for every HTTP run: the URL's host is the target, so drive --http with a
    scenario of statements only is refused without the flag, as a corpus endpoint run is."""
    code = cli.main(
        ["drive", "--http", "https://mcp.example.test:443/mcp", "--scenario", str(ALL_SIGNALS),
         "--out-dir", str(tmp_path / "runs")]
    )  # fmt: skip

    assert code == 2
    assert "--engagement-confirmed" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_observing_over_http_without_a_scenario_is_not_gated(tmp_path, poison_url):
    """Without a scenario and with a script that only lists, the gate does not apply over HTTP
    either (here: a loopback URL, so nothing beyond it is reached)."""
    assert cli.main(["drive", "-q", "--http", poison_url, "--out-dir", str(tmp_path / "r")]) == 0
